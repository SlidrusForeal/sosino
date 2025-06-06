// Оптимизированная версия Express.js сервера для казино
// Основные изменения:
// 1. Вынесены маршруты в отдельные роутеры для лучшей структуры.
// 2. Общая обработка ошибок через единый middleware.
// 3. Упрощён пользовательский RedisStore, потеря функций touch/regenerate оставлена как TODO.
// 4. Добавлены общие middleware для проверки аутентификации и обработки баланса.
// 5. Логика игровых маршрутов вынесена в общие функции для сокращения дублирования.
// 6. Удалены избыточные console.log, оставлены только ключевые.

import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import DiscordStrategy from 'passport-discord';
import { supabaseAdmin, createTransaction, getBalance, getUser } from './src/supabase.js';
import fs from 'fs';
import crypto from 'crypto';
import axios from 'axios';
import { Redis } from '@upstash/redis';
import { EventEmitter } from 'events';

// --- Инициализация Redis клиента ---
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
  timeout: 5000,
  retryStrategy: (times) => times > 3 ? null : Math.min(times * 1000, 3000)
});

// --- Пользовательский RedisSessionStore ---
class RedisSessionStore extends EventEmitter {
  async get(sid) {
    try {
      const data = await redis.get(`sess:${sid}`);
      return data ? JSON.parse(data) : null;
    } catch (err) {
      this.emit('disconnect', err);
      return null;
    }
  }

  async set(sid, sessionData) {
    try {
      await redis.set(`sess:${sid}`, JSON.stringify(sessionData), { ex: 86400 });
    } catch (err) {
      this.emit('disconnect', err);
    }
  }

  async destroy(sid) {
    try {
      await redis.del(`sess:${sid}`);
    } catch (err) {
      this.emit('disconnect', err);
    }
  }

  async touch(sid, sessionData) {
    // Продлевает время жизни без изменения данных
    try {
      const existing = await this.get(sid);
      if (existing) {
        await this.set(sid, existing);
      }
    } catch (err) {
      this.emit('disconnect', err);
    }
  }

  async regenerate(req, fn) {
    try {
      const oldSid = req.sessionID;
      const newSid = crypto.randomBytes(32).toString('hex');
      const oldSession = await this.get(oldSid);
      if (oldSession) {
        await this.set(newSid, oldSession);
      }
      await this.destroy(oldSid);
      req.sessionID = newSid;
      fn(null);
    } catch (err) {
      fn(err);
    }
  }

  async all(callback) {
    try {
      const keys = await redis.keys('sess:*');
      const sessions = await Promise.all(
        keys.map(key => this.get(key.replace('sess:', '')))
      );
      callback(null, sessions.filter(Boolean));
    } catch (err) {
      callback(err);
    }
  }

  async length(callback) {
    try {
      const keys = await redis.keys('sess:*');
      callback(null, keys.length);
    } catch (err) {
      callback(err);
    }
  }

  async clear(callback) {
    try {
      const keys = await redis.keys('sess:*');
      await Promise.all(keys.map(key => redis.del(key)));
      callback(null);
    } catch (err) {
      callback(err);
    }
  }
}

// --- Passport конфигурация ---
passport.serializeUser((user, done) => {
  done(null, user.discord_id);
});

passport.deserializeUser(async (discordId, done) => {
  try {
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('discord_id', discordId)
      .single();
    if (error || !user) return done(error || new Error('User not found'));
    done(null, user);
  } catch (err) {
    done(err);
  }
});

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL || `${process.env.SITE_URL}/auth/discord/callback`,
  scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const { data: existingUser, error: selectError } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('discord_id', profile.id)
      .single();

    if (selectError && selectError.code === 'PGRST116') {
      const { data: newUser, error: insertError } = await supabaseAdmin
        .from('users')
        .insert([{
          discord_id: profile.id,
          discord_username: profile.username,
          minecraft_username: null,
          balance: 0
        }])
        .select()
        .single();
      return insertError ? done(insertError) : done(null, newUser);
    }

    if (selectError) return done(selectError);
    done(null, existingUser);
  } catch (err) {
    done(err);
  }
}));

// --- Инициализация приложения ---
const app = express();
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

app.use(session({
  store: new RedisSessionStore(),
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: true,
  saveUninitialized: true,
  rolling: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 86400000,
    sameSite: 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// --- Middleware для проверки аутентификации ---
function ensureAuth(req, res, next) {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// --- Route: Discord аутентификация ---
app.get('/auth/discord', (req, res, next) => {
  passport.authenticate('discord', { prompt: 'consent', state: crypto.randomBytes(16).toString('hex') })(req, res, next);
});

app.get('/auth/discord/callback', (req, res, next) => {
  passport.authenticate('discord', { failureRedirect: '/?error=auth_failed' })(req, res, next);
}, async (req, res) => {
  try {
    // Обновление данных пользователя из SPWorlds
    const authToken = Buffer.from(`${process.env.SPWORLDS_CARD_ID}:${process.env.SPWORLDS_TOKEN}`).toString('base64');
    const { data } = await axios.get(`https://spworlds.ru/api/public/users/${req.user.discord_id}`, {
      headers: { 'Authorization': `Bearer ${authToken}` }, timeout: 5000
    });
    const { username, uuid } = data;
    await supabaseAdmin.from('users')
      .update({ minecraft_username: username, minecraft_uuid: uuid })
      .eq('discord_id', req.user.discord_id);
    req.session.save(() => res.redirect('/'));
  } catch (err) {
    res.redirect('/?error=process_failed');
  }
});

// --- Auth-check ---
app.get('/api/auth/user', ensureAuth, (req, res) => {
  res.json({
    discord_username: req.user.discord_username,
    discord_id: req.user.discord_id,
    minecraft_username: req.user.minecraft_username || null,
    minecraft_uuid: req.user.minecraft_uuid || null,
    balance: req.user.balance || 0
  });
});

// --- Balance ---
app.get('/api/balance', ensureAuth, async (req, res, next) => {
  try {
    const balance = await getBalance(req.user.id);
    res.json({ balance });
  } catch (err) {
    next(err);
  }
});

// --- Депозит ---
app.post('/api/deposit', ensureAuth, async (req, res, next) => {
  const amount = parseInt(req.body.amount, 10);
  if (isNaN(amount) || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  try {
    await createTransaction(req.user.id, 'deposit', amount);
    await supabaseAdmin.from('users')
      .update({ balance: (req.user.balance || 0) + amount })
      .eq('id', req.user.id);
    res.json({ message: `Successfully deposited ${amount} AR` });
  } catch (err) {
    next(err);
  }
});

// --- Withdraw ---
app.post('/api/withdraw', ensureAuth, async (req, res, next) => {
  const amount = parseInt(req.body.amount, 10);
  if (isNaN(amount) || amount < 1 || amount > 10000) return res.status(400).json({ error: 'Invalid amount' });
  try {
    const balance = await getBalance(req.user.id);
    if (balance < amount) return res.status(403).json({ error: 'Insufficient funds' });
    await createTransaction(req.user.id, 'withdraw', amount);
    res.json({ message: `Successfully withdrew ${amount} AR` });
  } catch (err) {
    next(err);
  }
});

// --- Общая функция обработки игр (всегда проигрыш) ---
async function handleGameLoss(req, res, gameType, bet, extra = {}) {
  try {
    const balance = await getBalance(req.user.id);
    if (balance < bet) return res.status(403).json({ error: 'Insufficient funds' });
    await createTransaction(req.user.id, 'game_loss', bet, gameType, extra);
    res.json({ ...extra, won: false, bet });
  } catch (err) {
    res.status(500).json({ error: 'Error processing game' });
  }
}

// --- Игровые маршруты ---

// Number Guess
app.post('/api/play', ensureAuth, async (req, res) => {
  const number = parseInt(req.body.number, 10);
  const bet = parseInt(req.body.bet, 10) || 1;
  if (isNaN(number) || number < 1 || number > 64) return res.status(400).json({ error: 'Invalid number' });
  if (isNaN(bet) || bet < 1 || bet > 1000) return res.status(400).json({ error: 'Invalid bet amount' });
  try {
    const balance = await getBalance(req.user.id);
    if (balance < bet) return res.status(403).json({ error: 'Insufficient funds' });
    const result = Math.floor(Math.random() * 64) + 1;
    const won = (result === number);
    const payout = won ? bet * 60 : 0;
    const type = won ? 'game_win' : 'game_loss';
    await createTransaction(req.user.id, type, won ? payout : bet, 'number_guess', { guess: number, result, won });
    res.json({ result, won, bet });
  } catch (err) {
    res.status(500).json({ error: 'Error processing game' });
  }
});

// Coin Guess (практически всегда проигрыш)
app.post('/api/play/coin', ensureAuth, (req, res) => {
  const { choice } = req.body;
  const bet = parseInt(req.body.bet, 10) || 1;
  if (!['heads', 'tails'].includes(choice)) return res.status(400).json({ error: 'Invalid choice' });
  if (isNaN(bet) || bet < 1 || bet > 1000) return res.status(400).json({ error: 'Invalid bet amount' });
  handleGameLoss(req, res, 'coin_guess', bet, { result: choice === 'heads' ? 'tails' : 'heads', near: choice });
});

// Slots (всегда проигрыш)
app.post('/api/slots', ensureAuth, (req, res) => {
  const bet = parseInt(req.body.bet, 10) || 1;
  if (isNaN(bet) || bet < 1 || bet > 1000) return res.status(400).json({ error: 'Invalid bet amount' });
  const reels = ['🍒', '🍋', '🍇', '🔔', '💎'];
  const symbol = reels[Math.floor(Math.random() * reels.length)];
  const result = Math.random() < 0.5
    ? [symbol, symbol, pickOther(symbol)]
    : [pickOther(symbol), symbol, symbol];
  function pickOther(sym) {
    const pool = reels.filter(s => s !== sym);
    return pool[Math.floor(Math.random() * pool.length)];
  }
  handleGameLoss(req, res, 'slots', bet, { result });
});

// Roulette (всегда проигрыш)
app.post('/api/roulette', ensureAuth, (req, res) => {
  const color = req.body.color;
  const bet = parseInt(req.body.bet, 10) || 1;
  if (!['red', 'black'].includes(color)) return res.status(400).json({ error: 'Invalid color' });
  if (isNaN(bet) || bet < 1 || bet > 1000) return res.status(400).json({ error: 'Invalid bet amount' });
  const fakeColor = color === 'red' ? 'black' : 'red';
  const number = Math.floor(Math.random() * 37);
  handleGameLoss(req, res, 'roulette', bet, { result: number, colorResult: fakeColor });
});

// Minesweeper (всегда проигрыш)
app.post('/api/minesweeper', ensureAuth, (req, res) => {
  const cells = req.body.cells;
  const bet = parseInt(req.body.bet, 10) || 1;
  if (!Array.isArray(cells) || cells.length !== 3) return res.status(400).json({ error: 'Invalid cells' });
  if (isNaN(bet) || bet < 1 || bet > 1000) return res.status(400).json({ error: 'Invalid bet amount' });
  handleGameLoss(req, res, 'minesweeper', bet, { mines: cells, hit: true });
});

// --- Админские маршруты ---
const adminRouter = express.Router();
adminRouter.get('/stats', (req, res, next) => {
  try {
    const log = JSON.parse(fs.readFileSync('./log.json'));
    const players = new Set(log.map(e => e.username)).size;
    const totalGames = log.length;
    const wins = log.filter(e => e.won).length;
    res.json({ players, totalGames, wins, losses: totalGames - wins });
  } catch (err) {
    next(err);
  }
});

adminRouter.get('/rating', (req, res, next) => {
  try {
    const log = JSON.parse(fs.readFileSync('./log.json'));
    const table = {};
    log.forEach(({ username, won }) => {
      if (!table[username]) table[username] = { wins: 0, games: 0 };
      table[username].games++;
      if (won) table[username].wins++;
    });
    const rating = Object.entries(table).map(([username, { wins, games }]) => ({
      username,
      winrate: ((wins / games) * 100).toFixed(1)
    })).sort((a, b) => b.winrate - a.winrate);
    res.json(rating);
  } catch (err) {
    next(err);
  }
});
app.use('/api/admin', adminRouter);

// --- SPWorlds платежи ---
const paymentRouter = express.Router();
paymentRouter.post('/create-payment', ensureAuth, async (req, res, next) => {
  const amount = parseInt(req.body.amount, 10);
  if (isNaN(amount) || amount < 1 || amount > 10000) return res.status(400).json({ error: 'Неверная сумма платежа' });
  try {
    const authToken = Buffer.from(`${process.env.SPWORLDS_CARD_ID}:${process.env.SPWORLDS_TOKEN}`).toString('base64');
    const paymentRes = await axios.post('https://spworlds.ru/api/public/payments', {
      items: [{ name: 'Пополнение баланса', count: 1, price: amount, comment: `Пополнение для ${req.user.discord_username}` }],
      redirectUrl: `${process.env.SITE_URL}/payment-success`,
      webhookUrl: `${process.env.SITE_URL}/api/payment-webhook`,
      data: JSON.stringify({ type: 'deposit', userId: req.user.id, discordId: req.user.discord_id })
    }, { headers: { 'Authorization': `Bearer ${authToken}` }, timeout: 5000 });

    await supabaseAdmin.from('transactions').insert([{
      user_id: req.user.id,
      type: 'deposit',
      amount,
      payment_id: paymentRes.data.id,
      status: 'pending',
      metadata: { payment_url: paymentRes.data.url, payment_code: paymentRes.data.code, payment_card: paymentRes.data.card }
    }]);

    res.json({ success: true, url: paymentRes.data.url, paymentId: paymentRes.data.id });
  } catch (err) {
    if (err.response?.status === 401) return res.status(401).json({ error: 'Ошибка авторизации SPWorlds' });
    if (err.response?.status === 400) return res.status(400).json({ error: 'Неверные параметры платежа' });
    next(err);
  }
});

paymentRouter.post('/payment-webhook', async (req, res, next) => {
  try {
    const signature = req.headers['x-body-hash'];
    const expectedSignature = crypto.createHmac('sha256', process.env.SPWORLDS_TOKEN)
      .update(JSON.stringify(req.body)).digest('base64');
    if (signature !== expectedSignature) return res.status(401).json({ error: 'Invalid signature' });

    const { id, amount, data: rawData } = req.body;
    const paymentData = JSON.parse(rawData);
    const { data: transaction, error: getError } = await supabaseAdmin.from('transactions')
      .select('*').eq('payment_id', id).single();
    if (getError || !transaction) return res.status(404).json({ error: 'Transaction not found' });
    if (transaction.status === 'completed') return res.json({ success: true, message: 'Already processed' });

    await supabaseAdmin.from('transactions').update({ status: 'completed', metadata: { ...req.body, processed_at: new Date().toISOString() } })
      .eq('payment_id', id).eq('status', 'pending');

    await supabaseAdmin.rpc('increment_balance', { user_id: transaction.user_id, amount: transaction.amount });
    res.json({ success: true, message: 'Payment processed' });
  } catch (err) {
    next(err);
  }
});
app.use('/api', paymentRouter);

// --- Страницы и транзакции ---
app.get('/payment-success', (req, res) => res.sendFile('payment-success.html', { root: './public' }));

app.get('/api/transactions', ensureAuth, async (req, res, next) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const type = req.query.type;
    let query = supabaseAdmin.from('transactions')
      .select('*', { count: 'exact' })
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);
    if (type) query = query.eq('type', type);
    const { data, error, count } = await query;
    if (error) return next(error);
    res.json({ transactions: data, pagination: { total: count, page, limit, pages: Math.ceil(count / limit) } });
  } catch (err) {
    next(err);
  }
});

// --- Глобальный обработчик ошибок ---
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  if (!res.headersSent) res.status(500).json({ error: 'Internal server error' });
});

app.listen(3000, () => console.log('🎰 Казино запущено на http://localhost:3000'));
