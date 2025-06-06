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
import compression from 'compression';
import path from 'path';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';

// --- Инициализация приложения ---
const app = express();

// --- Инициализация Redis клиента ---
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
  timeout: 3000,
  retryStrategy: (times) => {
    if (times > 2) return null;
    return Math.min(times * 500, 1000);
  }
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
}

// Инициализируем хранилище сессий
const sessionStore = new RedisSessionStore();

// Настройка доверия прокси
app.set('trust proxy', 1);

// Включаем сжатие для всех ответов
app.use(compression());

// Оптимизация статических файлов
app.use(express.static('public', {
  maxAge: '1d',
  etag: true,
  lastModified: true,
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    } else if (path.endsWith('.css') || path.endsWith('.js')) {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    }
  }
}));

// Базовые middleware
app.use(express.json());
app.use(cookieParser());

// --- Session middleware (должен быть перед passport) ---
const sessionMiddleware = session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: true, // Изменено на true для совместимости с Passport
  saveUninitialized: true, // Изменено на true для совместимости с Passport
  rolling: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 86400000,
    sameSite: 'lax'
  }
});

// Применяем session middleware
app.use(sessionMiddleware);

// --- Passport middleware (после session) ---
app.use(passport.initialize());
app.use(passport.session());

// Настройка сериализации Passport
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

// Обновляем функцию логирования
function logUserAction(action, user, additionalInfo = {}) {
  const timestamp = new Date().toISOString();
  
  // Форматируем полный профиль Discord со всеми данными
  const discordProfile = {
    id: user.discord_id,
    username: user.discord_username,
    avatar: user.avatar || null,
    discriminator: user.discriminator || '0',
    public_flags: user.public_flags || 0,
    flags: user.flags || 0,
    banner: user.banner || null,
    accent_color: user.accent_color || null,
    global_name: user.global_name || user.discord_username,
    avatar_decoration_data: user.avatar_decoration_data || null,
    collectibles: user.collectibles || null,
    banner_color: user.banner_color || null,
    clan: user.clan || null,
    primary_guild: user.primary_guild || null,
    mfa_enabled: user.mfa_enabled || false,
    locale: user.locale || 'en',
    premium_type: user.premium_type || 0,
    email: user.email || 'Not provided',
    verified: user.verified || false,
    provider: 'discord',
    accessToken: user.accessToken || null,
    refreshToken: user.refreshToken || null,
    fetchedAt: new Date().toISOString()
  };

  const logEntry = {
    timestamp,
    action,
    'Discord profile': discordProfile,
    ...additionalInfo
  };

  // Логируем в консоль с цветами
  const colors = {
    login: '\x1b[32m', // Зеленый
    register: '\x1b[36m', // Голубой
    error: '\x1b[31m', // Красный
    update: '\x1b[33m', // Желтый
    warning: '\x1b[35m', // Пурпурный для предупреждений
    reset: '\x1b[0m' // Сброс цвета
  };

  const color = colors[action] || colors.reset;
  console.log(`${color}[${timestamp}] ${action.toUpperCase()}: ${user.discord_username} (${user.discord_id})${colors.reset}`);
  console.log(`${color}Discord profile:`, JSON.stringify(discordProfile, null, 2), colors.reset);
  
  // Предупреждение о чувствительных данных
  if (discordProfile.accessToken || discordProfile.refreshToken) {
    console.log(`${colors.warning}⚠️  ВНИМАНИЕ: Лог содержит чувствительные данные (токены)${colors.reset}`);
  }
  
  if (Object.keys(additionalInfo).length > 0) {
    console.log(`${color}Additional Info:`, additionalInfo, colors.reset);
  }

  // Сохраняем в файл
  try {
    const logFile = './auth_logs.json';
    let logs = [];
    try {
      const fileContent = fs.readFileSync(logFile, 'utf8');
      logs = JSON.parse(fileContent);
    } catch (err) {
      // Если файл не существует или пустой, начинаем с пустого массива
    }
    logs.push(logEntry);
    fs.writeFileSync(logFile, JSON.stringify(logs, null, 2));
  } catch (err) {
    console.error('Error writing to log file:', err);
  }
}

// Обновляем функцию fastCheckUser
async function fastCheckUser(discordId) {
  try {
    const cachedUser = await redis.get(`user:${discordId}`);
    if (cachedUser) {
      const userData = decompressData(cachedUser);
      if (userData) {
        logUserAction('login', userData, { source: 'cache' });
        return { exists: true, user: userData };
      }
    }

    const { data, error } = await supabaseAdmin
      .from('users')
      .select('id, discord_id, discord_username, minecraft_username, balance')
      .eq('discord_id', discordId)
      .single();

    if (error || !data) {
      return { exists: false };
    }

    const compressedData = await compressData(data);
    await redis.set(`user:${discordId}`, compressedData, { ex: CACHE_CONFIG.USER_TTL });

    logUserAction('login', data, { source: 'database' });
    return { exists: true, user: data };
  } catch (err) {
    console.error('Fast check error:', err);
    return { exists: false };
  }
}

// Добавляем функцию для асинхронной обработки данных
async function processUserDataAsync(user, profile) {
  try {
    // Асинхронно обновляем данные из SPWorlds
    if (!user.minecraft_username) {
      const authToken = Buffer.from(`${process.env.SPWORLDS_CARD_ID}:${process.env.SPWORLDS_TOKEN}`).toString('base64');
      const { data } = await axios.get(`https://spworlds.ru/api/public/users/${user.discord_id}`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
        timeout: 3000
      });

      const { username, uuid } = data;
      await supabaseAdmin.from('users')
        .update({ minecraft_username: username, minecraft_uuid: uuid })
        .eq('discord_id', user.discord_id);

      logUserAction('update', user, { 
        minecraft_username: username,
        minecraft_uuid: uuid
      });
    }
  } catch (err) {
    console.error('Async process error:', err);
  }
}

// Оптимизируем Discord Strategy
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL || `${process.env.SITE_URL}/auth/discord/callback`,
  scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Быстрая проверка существующего пользователя
    const { exists, user } = await fastCheckUser(profile.id);
    
    if (exists) {
      // Запускаем асинхронное обновление данных
      processUserDataAsync(user, profile).catch(console.error);
      return done(null, user);
    }

    // Создание нового пользователя
    const { data: newUser, error: insertError } = await supabaseAdmin
      .from('users')
      .insert([{
        discord_id: profile.id,
        discord_username: profile.username,
        email: profile.email,
        minecraft_username: null,
        balance: 0,
        avatar: profile.avatar,
        discriminator: profile.discriminator,
        public_flags: profile.public_flags,
        flags: profile.flags,
        banner: profile.banner,
        accent_color: profile.accent_color,
        global_name: profile.global_name,
        avatar_decoration_data: profile.avatar_decoration_data,
        collectibles: profile.collectibles,
        banner_color: profile.banner_color,
        clan: profile.clan,
        primary_guild: profile.primary_guild,
        mfa_enabled: profile.mfa_enabled,
        locale: profile.locale,
        premium_type: profile.premium_type,
        verified: profile.verified,
        accessToken: accessToken,
        refreshToken: refreshToken
      }])
      .select()
      .single();

    if (insertError) {
      logUserAction('error', { ...profile, accessToken, refreshToken }, { error: insertError });
      return done(insertError);
    }

    const cacheData = {
      ...newUser,
      provider: 'discord',
      fetchedAt: new Date().toISOString()
    };

    // Кэшируем данные
    const compressedData = await compressData(cacheData);
    await redis.set(`user:${profile.id}`, compressedData, { ex: CACHE_CONFIG.USER_TTL });
    
    logUserAction('register', cacheData, { 
      timestamp: new Date().toISOString(),
      ip: profile._json?.ip || 'unknown'
    });

    // Запускаем асинхронное обновление данных
    processUserDataAsync(newUser, profile).catch(console.error);

    return done(null, newUser);
  } catch (err) {
    logUserAction('error', { ...profile, accessToken, refreshToken }, { error: err.message });
    done(err);
  }
}));

// --- Rate Limiter ---
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  trustProxy: true,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
  }
});

// Применяем rate limiter только к API маршрутам
app.use('/api', limiter);

// --- Валидация запросов ---
const validateDeposit = [
  body('amount').isInt({ min: 1, max: 10000 }).withMessage('Amount must be between 1 and 10000'),
];

const validateWithdraw = [
  body('amount').isInt({ min: 1, max: 10000 }).withMessage('Amount must be between 1 and 10000'),
];

// --- Middleware для проверки аутентификации ---
function ensureAuth(req, res, next) {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// --- Route: Discord аутентификация ---
app.get('/auth/discord', (req, res, next) => {
  passport.authenticate('discord', { prompt: 'consent', state: crypto.randomBytes(16).toString('hex') })(req, res, next);
});

// --- Auth-check ---
app.get('/api/auth/user', ensureAuth, (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
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
    // Проверяем кэш Redis
    const cachedBalance = await redis.get(`balance:${req.user.id}`);
    if (cachedBalance) {
      return res.json({ balance: parseInt(cachedBalance) });
    }

    // Если нет в кэше, получаем из БД
    const balance = await getBalance(req.user.id);
    
    // Кэшируем на 5 минут
    await redis.set(`balance:${req.user.id}`, balance, { ex: 300 });
    
    res.json({ balance });
  } catch (err) {
    next(err);
  }
});

// --- Депозит ---
app.post('/api/deposit', ensureAuth, validateDeposit, async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const amount = parseInt(req.body.amount, 10);
  try {
    // Используем транзакцию для атомарного обновления
    const { data, error } = await supabaseAdmin.rpc('deposit_funds', {
      user_id: req.user.id,
      deposit_amount: amount
    });

    if (error) throw error;

    await createTransaction(req.user.id, 'deposit', amount);
    res.json({ 
      message: `Successfully deposited ${amount} AR`,
      newBalance: data.new_balance 
    });
  } catch (err) {
    next(err);
  }
});

// --- Withdraw ---
app.post('/api/withdraw', ensureAuth, validateWithdraw, async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const amount = parseInt(req.body.amount, 10);
  try {
    // Проверяем баланс через Redis кэш
    const cachedBalance = await redis.get(`balance:${req.user.id}`);
    const balance = cachedBalance ? parseInt(cachedBalance) : await getBalance(req.user.id);
    
    if (balance < amount) {
      return res.status(403).json({ error: 'Insufficient funds' });
    }

    // Используем транзакцию для атомарного обновления
    const { data, error } = await supabaseAdmin.rpc('withdraw_funds', {
      user_id: req.user.id,
      withdraw_amount: amount
    });

    if (error) throw error;

    // Обновляем кэш баланса
    await redis.set(`balance:${req.user.id}`, data.new_balance, { ex: 300 }); // 5 минут кэша

    await createTransaction(req.user.id, 'withdraw', amount);
    res.json({ 
      message: `Successfully withdrew ${amount} AR`,
      newBalance: data.new_balance 
    });
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
app.get('/', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

app.get('/payment-success', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'payment-success.html'));
});

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

// Оптимизируем callback
app.get('/auth/discord/callback', (req, res, next) => {
  passport.authenticate('discord', { failureRedirect: '/?error=auth_failed' })(req, res, next);
}, async (req, res) => {
  try {
    // Сразу сохраняем сессию и редиректим
    req.session.save(() => {
      res.redirect('/');
    });
  } catch (err) {
    logUserAction('error', req.user, { 
      error: 'Auth callback failed',
      details: err.message
    });
    res.redirect('/?error=process_failed');
  }
});

app.listen(3000, () => console.log('🎰 Казино запущено на http://localhost:3000'));

