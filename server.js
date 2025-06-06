import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import DiscordStrategy from 'passport-discord';
import { supabase, supabaseAdmin, createTransaction, getBalance, getUser } from './src/supabase.js';
import fs from 'fs';
import crypto from 'crypto';
import axios from 'axios';
import rateLimit from 'express-rate-limit';

// Custom Session Store using Supabase
class SupabaseStore extends session.Store {
  constructor() {
    super();
    this.ttl = 86400; // 24 hours in seconds
    this.ensureTableExists();
    this.startCleanupInterval();
  }

  async ensureTableExists() {
    try {
      // Check if table exists
      const { error: checkError } = await supabaseAdmin
        .from('sessions')
        .select('count')
        .limit(1);

      if (checkError && checkError.code === '42P01') { // Table doesn't exist
        console.log('Creating sessions table...');
        const { error: createError } = await supabaseAdmin.rpc('create_sessions_table');
        if (createError) {
          console.error('Error creating sessions table:', createError);
        } else {
          console.log('Sessions table created successfully');
        }
      }
    } catch (err) {
      console.error('Error ensuring sessions table exists:', err);
    }
  }

  startCleanupInterval() {
    // Run cleanup every hour
    setInterval(async () => {
      try {
        const { error } = await supabaseAdmin.rpc('cleanup_expired_sessions');
        if (error) {
          console.error('Error cleaning up expired sessions:', error);
        }
      } catch (err) {
        console.error('Error in cleanup interval:', err);
      }
    }, 60 * 60 * 1000); // 1 hour
  }

  async get(sid, callback) {
    try {
      console.log('Getting session:', sid); // Debug log
      const { data, error } = await supabaseAdmin
        .from('sessions')
        .select('*')
        .eq('sid', sid)
        .maybeSingle();

      if (error) {
        console.error('Session get error:', error);
        return callback(error);
      }

      if (!data) {
        console.log('No session found for:', sid); // Debug log
        return callback(null, null);
      }

      // Check if session is expired
      if (data.expires_at && new Date(data.expires_at) < new Date()) {
        console.log('Session expired for:', sid); // Debug log
        await this.destroy(sid);
        return callback(null, null);
      }

      try {
        const session = JSON.parse(data.session);
        console.log('Retrieved session data:', {
          sid,
          hasPassport: !!session.passport,
          passportUser: session.passport?.user
        }); // Debug log
        callback(null, session);
      } catch (parseError) {
        console.error('Error parsing session data:', parseError);
        callback(null, null);
      }
    } catch (err) {
      console.error('Unexpected error in session get:', err);
      callback(null, null);
    }
  }

  async set(sid, session, callback) {
    try {
      console.log('Setting session:', {
        sid,
        hasPassport: !!session.passport,
        passportUser: session.passport?.user
      }); // Debug log

      const expiresAt = new Date(Date.now() + this.ttl * 1000);
      const sessionData = {
        sid,
        session: JSON.stringify(session),
        expires_at: expiresAt.toISOString()
      };

      const { error } = await supabaseAdmin
        .from('sessions')
        .upsert(sessionData, {
          onConflict: 'sid'
        });

      if (error) {
        console.error('Session set error:', error);
        return callback(error);
      }

      console.log('Session set successfully:', sid); // Debug log
      callback();
    } catch (err) {
      console.error('Unexpected error in session set:', err);
      callback(err);
    }
  }

  async destroy(sid, callback) {
    try {
      console.log('Destroying session:', sid); // Debug log
      const { error } = await supabaseAdmin
        .from('sessions')
        .delete()
        .eq('sid', sid);

      if (error) {
        console.error('Session destroy error:', error);
        return callback(error);
      }

      console.log('Session destroyed successfully:', sid); // Debug log
      callback();
    } catch (err) {
      console.error('Unexpected error in session destroy:', err);
      callback(err);
    }
  }

  async touch(sid, session, callback) {
    try {
      console.log('Touching session:', sid); // Debug log
      const expiresAt = new Date(Date.now() + this.ttl * 1000);
      const { error } = await supabaseAdmin
        .from('sessions')
        .update({
          expires_at: expiresAt.toISOString(),
          session: JSON.stringify(session) // Update session data as well
        })
        .eq('sid', sid);

      if (error) {
        console.error('Session touch error:', error);
        return callback(error);
      }

      console.log('Session touched successfully:', sid); // Debug log
      callback();
    } catch (err) {
      console.error('Unexpected error in session touch:', err);
      callback(err);
    }
  }
}

// Debug log for SPWorlds credentials
console.log('SPWorlds Credentials:', {
  cardId: process.env.SPWORLDS_CARD_ID ? 'Card ID is set' : 'Card ID is missing',
  token: process.env.SPWORLDS_TOKEN ? 'Token is set' : 'Token is missing'
});

const app = express();

// Включаем доверие к прокси
app.set('trust proxy', 1);

// 1) Статические файлы и JSON-парсинг
app.use(express.static('public'));
app.use(express.json());

// 2) Сессии
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: true,
  saveUninitialized: true,
  rolling: true,
  store: new SupabaseStore(),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax',
    domain: process.env.NODE_ENV === 'production' ? '.sosmark.ru' : undefined
  }
}));

// Debug middleware to log session state
app.use((req, res, next) => {
  console.log('Session state:', {
    id: req.sessionID,
    hasSession: !!req.session,
    hasUser: !!req.user,
    sessionData: req.session,
    passport: req.session?.passport,
    cookies: req.cookies
  });
  next();
});

// 3) Cookie-парсер
app.use(cookieParser());

// 4) Passport-инициализация
app.use(passport.initialize());
app.use(passport.session());

// --- Настройка Passport-Discord ---
passport.serializeUser((user, done) => {
  console.log('Serializing user:', user); // Debug log
  if (!user) {
    console.error('No user to serialize');
    return done(null, null);
  }
  
  // Store complete user data
  const userData = {
    id: user.id,
    discord_id: user.discord_id,
    discord_username: user.discord_username,
    minecraft_username: user.minecraft_username,
    minecraft_uuid: user.minecraft_uuid,
    balance: user.balance
  };
  console.log('Serialized user data:', userData); // Debug log
  done(null, userData);
});

passport.deserializeUser(async (userData, done) => {
  console.log('Deserializing user data:', userData); // Debug log
  try {
    if (!userData || !userData.discord_id) {
      console.error('Invalid user data during deserialization');
      return done(null, false);
    }

    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('discord_id', userData.discord_id)
      .maybeSingle();

    if (error) {
      console.error('Error deserializing user:', error);
      return done(error);
    }

    if (!user) {
      console.error('User not found during deserialization');
      return done(null, false);
    }

    console.log('Deserialized user:', user);
    done(null, user);
  } catch (error) {
    console.error('Error in deserializeUser:', error);
    done(error);
  }
});

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL || `${process.env.SITE_URL}/auth/discord/callback`,
  scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    console.log('Discord profile:', profile); // Debug log

    // Check if user exists in Supabase
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('discord_id', profile.id)
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        // User not found, create new user
        console.log('Creating new user...'); // Debug log
        try {
          const { data: newUser, error: createError } = await supabaseAdmin
            .from('users')
            .insert([
              {
                discord_id: profile.id,
                discord_username: profile.username,
                minecraft_username: null,
                balance: 0
              }
            ])
            .select()
            .single();

          if (createError) {
            console.error('Error creating user:', createError); // Debug log
            return done(createError);
          }
          console.log('New user created:', newUser); // Debug log
          return done(null, newUser);
        } catch (createError) {
          console.error('Error in user creation:', createError);
          return done(createError);
        }
      } else {
        // Other Supabase error
        console.error('Supabase error:', error); // Debug log
        return done(error);
      }
    }

    console.log('Existing user found:', user); // Debug log
    return done(null, user);
  } catch (error) {
    console.error('Passport strategy error:', error); // Debug log
    return done(error);
  }
}));

// --- Маршрут для авторизации через Discord ---
app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', 
  passport.authenticate('discord', { 
    failureRedirect: '/',
    failureMessage: true
  }), 
  async (req, res) => {
    try {
      console.log('Auth callback - User:', req.user); // Debug log

      // Get user info from SPWorlds API
      const spworldsResponse = await axios.get(`https://spworlds.ru/api/public/users/${req.user.discord_id}`, {
        headers: {
          'Authorization': `Bearer ${Buffer.from(`${process.env.SPWORLDS_CARD_ID}:${process.env.SPWORLDS_TOKEN}`).toString('base64')}`,
          'Content-Type': 'application/json'
        }
      });

      const { username, uuid } = spworldsResponse.data;
      console.log('SPWorlds user data:', { username, uuid });

      // Update user in Supabase
      const { data: updatedUser, error } = await supabaseAdmin
        .from('users')
        .update({
          minecraft_username: username,
          minecraft_uuid: uuid
        })
        .eq('discord_id', req.user.discord_id)
        .select()
        .single();

      if (error) {
        console.error('Error updating user:', error);
        throw error;
      }

      // Обновляем данные пользователя в сессии
      req.session.passport = { user: updatedUser };
      req.session.save((err) => {
        if (err) {
          console.error('Error saving session:', err);
          return res.redirect('/');
        }
        
        console.log('Session saved with user data:', {
          sessionID: req.sessionID,
          user: req.session.passport.user
        });

        res.redirect('/');
      });
    } catch (error) {
      console.error('Error in Discord callback:', error);
      res.redirect('/');
    }
  }
);

// Добавляем rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 100, // максимум 100 запросов с одного IP
  message: { error: 'Too many requests, please try again later.' }
});

// Создаем отдельный лимитер для auth/user
const authUserLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 минута
  max: 5, // максимум 5 запросов в минуту
  message: { error: 'Too many authentication checks, please try again later.' }
});

// Применяем общий rate limiter ко всем API запросам
app.use('/api/', apiLimiter);

// --- Проверка, кто сейчас залогинен ---
app.get('/api/auth/user', authUserLimiter, async (req, res) => {
  try {
    // Проверяем наличие кэшированных данных в сессии
    if (req.session.lastAuthCheck && 
        Date.now() - req.session.lastAuthCheck < 30000) { // 30 секунд кэша
      return res.json(req.session.cachedUserData);
    }

    console.log('Auth user endpoint - Session:', {
      id: req.sessionID,
      passport: req.session.passport,
      user: req.user
    });

    if (!req.isAuthenticated()) {
      console.log('User not authenticated');
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Return user data from session
    const userData = {
      discord_username: req.user.discord_username,
      discord_id: req.user.discord_id,
      minecraft_username: req.user.minecraft_username || 'Unknown',
      minecraft_uuid: req.user.minecraft_uuid || null,
      balance: req.user.balance || 0
    };

    // Кэшируем данные
    req.session.lastAuthCheck = Date.now();
    req.session.cachedUserData = userData;

    console.log('Sending user data:', userData);
    return res.json(userData);
  } catch (err) {
    console.error('Error in /api/auth/user:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Добавляем middleware для проверки аутентификации с кэшированием
const ensureAuthenticated = (req, res, next) => {
  // Проверяем кэш аутентификации
  if (req.session.lastAuthCheck && 
      Date.now() - req.session.lastAuthCheck < 30000) { // 30 секунд кэша
    return next();
  }

  console.log('Checking authentication:', {
    isAuthenticated: req.isAuthenticated(),
    session: req.session,
    user: req.user
  });

  if (req.isAuthenticated()) {
    // Обновляем время последней проверки
    req.session.lastAuthCheck = Date.now();
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
};

// Применяем middleware ко всем защищенным маршрутам
app.use('/api/*', ensureAuthenticated);

// --- Выход из аккаунта ---
app.get('/auth/logout', (req, res) => {
  res.clearCookie('auth');
  res.redirect('/');
});

// --- Получение баланса пользователя ---
app.get('/api/balance', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const balance = await getBalance(req.user.supabaseId);
    return res.json({ balance });
  } catch (err) {
    console.error('Error getting balance:', err);
    return res.status(500).json({ error: 'Error getting balance' });
  }
});

// --- Депозит ---
app.post('/api/deposit', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const amount = parseInt(req.body.amount, 10);
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  try {
    // Create transaction record
    await createTransaction(req.user.id, 'deposit', amount);

    // Update user's balance
    const { error: updateError } = await supabaseAdmin
      .from('users')
      .update({ 
        balance: (req.user.balance || 0) + amount 
      })
      .eq('id', req.user.id);

    if (updateError) throw updateError;

    return res.json({ message: `Successfully deposited ${amount} AR` });
  } catch (err) {
    console.error('Error processing deposit:', err);
    return res.status(500).json({ error: 'Error processing deposit' });
  }
});

// --- Вывод средств ---
app.post('/api/withdraw', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { amount, card, comment } = req.body;
  if (isNaN(amount) || amount < 1 || amount > 10000) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  try {
    const balance = await getBalance(req.user.supabaseId);
    if (balance < amount) {
      return res.status(403).json({ error: 'Insufficient funds' });
    }

    await createTransaction(req.user.supabaseId, 'withdraw', amount);
    return res.json({ message: `Successfully withdrew ${amount} AR` });
  } catch (err) {
    console.error('Error processing withdrawal:', err);
    return res.status(500).json({ error: 'Error processing withdrawal' });
  }
});

// --- Игровые маршруты ---
app.post('/api/play', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const number = parseInt(req.body.number, 10);
  const bet = parseInt(req.body.bet, 10) || 1;

  if (isNaN(number) || number < 1 || number > 64) {
    return res.status(400).json({ error: 'Invalid number' });
  }

  if (isNaN(bet) || bet < 1 || bet > 1000) {
    return res.status(400).json({ error: 'Invalid bet amount' });
  }

  try {
    const balance = await getBalance(req.user.id);
    if (balance < bet) {
      return res.status(403).json({ error: 'Insufficient funds' });
    }

    const result = Math.floor(Math.random() * 64) + 1;
    const won = (result === number);

    // Record game result
    await createGameHistory(
      req.user.id,
      'number_guess',
      bet,
      won ? bet * 60 : 0,
      { guess: number, result, won }
    );

    // Record transaction
    if (won) {
      await createTransaction(req.user.id, 'game_win', bet * 60, 'number_guess');
    } else {
      await createTransaction(req.user.id, 'game_loss', bet, 'number_guess');
    }

    return res.json({ result, won, bet });
  } catch (err) {
    console.error('Error in game:', err);
    return res.status(500).json({ error: 'Error processing game' });
  }
});

app.post('/api/play/coin', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { choice } = req.body; // 'heads' или 'tails'
  const bet = parseInt(req.body.bet, 10) || 1;

  if (isNaN(bet) || bet < 1 || bet > 1000) {
    return res.status(400).json({ error: 'Invalid bet amount' });
  }

  try {
    const balance = await getBalance(req.user.id);
    if (balance < bet) {
      return res.status(403).json({ error: 'Insufficient funds' });
    }

    // Пример «подставного» варианта: игрок всегда проигрывает, но «почти» было противоположное
    const nearMiss = (choice === 'heads' ? 'heads' : 'tails');
    const finalResult = (choice === 'heads' ? 'tails' : 'heads');

    await createTransaction(req.user.id, 'game_loss', bet, 'coin_guess');
    return res.json({ result: finalResult, near: nearMiss, won: false, bet });
  } catch (err) {
    console.error('Error in coin game:', err);
    return res.status(500).json({ error: 'Error processing game' });
  }
});

app.post('/api/slots', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const bet = parseInt(req.body.bet, 10) || 1;

  if (isNaN(bet) || bet < 1 || bet > 1000) {
    return res.status(400).json({ error: 'Invalid bet amount' });
  }

  try {
    const balance = await getBalance(req.user.id);
    if (balance < bet) {
      return res.status(403).json({ error: 'Insufficient funds' });
    }

    // Create transaction for bet
    await createTransaction(req.user.id, 'game_loss', bet, 'slots');

    // Update user balance
    const { error: updateError } = await supabaseAdmin
      .from('users')
      .update({ balance: balance - bet })
      .eq('id', req.user.id);

    if (updateError) throw updateError;

    const reels = ['🍒', '🍋', '🍇', '🔔', '💎'];
    const result = [reels[0], reels[1], reels[2]];

    return res.json({ 
      result,
      won: false,
      bet,
      newBalance: balance - bet
    });
  } catch (err) {
    console.error('Error in slots game:', err);
    return res.status(500).json({ error: 'Error processing game' });
  }
});

app.post('/api/roulette', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { color } = req.body;
  const bet = parseInt(req.body.bet, 10) || 1;

  if (isNaN(bet) || bet < 1 || bet > 1000) {
    return res.status(400).json({ error: 'Invalid bet amount' });
  }

  try {
    const balance = await getBalance(req.user.id);
    if (balance < bet) {
      return res.status(403).json({ error: 'Insufficient funds' });
    }

    // Create transaction for bet
    await createTransaction(req.user.id, 'game_loss', bet, 'roulette');

    // Update user balance
    const { error: updateError } = await supabaseAdmin
      .from('users')
      .update({ balance: balance - bet })
      .eq('id', req.user.id);

    if (updateError) throw updateError;

    return res.json({ 
      result: Math.floor(Math.random() * 37),
      colorResult: color === 'red' ? 'black' : 'red',
      won: false,
      bet,
      newBalance: balance - bet
    });
  } catch (err) {
    console.error('Error in roulette game:', err);
    return res.status(500).json({ error: 'Error processing game' });
  }
});

app.post('/api/minesweeper', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { cells } = req.body;
  const bet = parseInt(req.body.bet, 10) || 1;

  if (isNaN(bet) || bet < 1 || bet > 1000) {
    return res.status(400).json({ error: 'Invalid bet amount' });
  }

  try {
    const balance = await getBalance(req.user.id);
    if (balance < bet) {
      return res.status(403).json({ error: 'Insufficient funds' });
    }

    // Create transaction for bet
    await createTransaction(req.user.id, 'game_loss', bet, 'minesweeper');

    // Update user balance
    const { error: updateError } = await supabaseAdmin
      .from('users')
      .update({ balance: balance - bet })
      .eq('id', req.user.id);

    if (updateError) throw updateError;

    return res.json({ 
      mines: cells,
      hit: true,
      won: false,
      bet,
      newBalance: balance - bet
    });
  } catch (err) {
    console.error('Error in minesweeper game:', err);
    return res.status(500).json({ error: 'Error processing game' });
  }
});

// --- Админские маршруты (статистика) ---
app.get('/api/admin/stats', async (req, res) => {
  const log = JSON.parse(fs.readFileSync('./log.json'));
  const players = new Set(log.map(e => e.username)).size;
  const totalGames = log.length;
  const wins = log.filter(e => e.won).length;
  const losses = totalGames - wins;
  return res.json({ players, totalGames, wins, losses });
});

app.get('/api/admin/rating', async (req, res) => {
  const log = JSON.parse(fs.readFileSync('./log.json'));
  const table = {};
  for (const entry of log) {
    if (!table[entry.username]) table[entry.username] = { wins: 0, games: 0 };
    table[entry.username].games++;
    if (entry.won) table[entry.username].wins++;
  }
  const rating = Object.entries(table)
    .map(([username, { wins, games }]) => ({
      username,
      winrate: ((wins / games) * 100).toFixed(1)
    }))
    .sort((a, b) => b.winrate - a.winrate);
  return res.json(rating);
});

// SPWorlds payment integration

// Create payment request
app.post('/api/create-payment', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { amount } = req.body;
  
  if (!amount || amount < 1 || amount > 10000) {
    return res.status(400).json({ error: 'Неверная сумма платежа' });
  }

  try {
    // Create base64 encoded auth token
    const authToken = Buffer.from(`${process.env.SPWORLDS_CARD_ID}:${process.env.SPWORLDS_TOKEN}`).toString('base64');

    // Create payment request to SPWorlds
    const paymentRes = await axios.post('https://spworlds.ru/api/public/payments', {
      items: [{
        name: 'Пополнение баланса',
        count: 1,
        price: amount,
        comment: `Пополнение баланса в казино для ${req.user.discord_username}`
      }],
      redirectUrl: `${process.env.SITE_URL || 'https://casino.sosmark.ru'}/payment-success`,
      webhookUrl: `${process.env.SITE_URL || 'https://casino.sosmark.ru'}/api/payment-webhook`,
      data: JSON.stringify({ 
        type: 'deposit',
        userId: req.user.id,
        discordId: req.user.discord_id
      })
    }, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Create pending transaction
    const { error: transactionError } = await supabaseAdmin
      .from('transactions')
      .insert([{
        user_id: req.user.id,
        type: 'deposit',
        amount: amount,
        payment_id: paymentRes.data.id,
        status: 'pending',
        metadata: {
          payment_url: paymentRes.data.url,
          payment_code: paymentRes.data.code,
          payment_card: paymentRes.data.card
        }
      }]);

    if (transactionError) {
      console.error('Error creating transaction:', transactionError);
      throw transactionError;
    }

    // Log successful payment creation
    console.log('Payment created:', {
      userId: req.user.id,
      amount,
      paymentId: paymentRes.data.id,
      paymentUrl: paymentRes.data.url,
      paymentCode: paymentRes.data.code,
      paymentCard: paymentRes.data.card
    });

    res.json({
      success: true,
      url: paymentRes.data.url,
      paymentId: paymentRes.data.id,
      paymentCode: paymentRes.data.code,
      paymentCard: paymentRes.data.card
    });
  } catch (error) {
    console.error('Payment creation error:', {
      error: error.response?.data || error.message,
      userId: req.user.id,
      amount,
      headers: error.config?.headers
    });

    // Send appropriate error message to client
    if (error.response?.status === 401) {
      return res.status(401).json({ error: 'Ошибка авторизации SPWorlds' });
    } else if (error.response?.status === 400) {
      return res.status(400).json({ error: 'Неверные параметры платежа' });
    } else {
      return res.status(500).json({ error: 'Ошибка при создании платежа' });
    }
  }
});

// Payment webhook handler
app.post('/api/payment-webhook', async (req, res) => {
  try {
    // Verify webhook signature
    const signature = req.headers['x-body-hash'];
    const body = JSON.stringify(req.body);
    const expectedSignature = crypto
      .createHmac('sha256', process.env.SPWORLDS_TOKEN)
      .update(body)
      .digest('base64');

    if (signature !== expectedSignature) {
      console.error('Invalid webhook signature');
      return res.status(401).json({ error: 'Invalid signature' });
    }

    const { payer, amount, data } = req.body;
    const paymentData = JSON.parse(data);
    
    // Get the transaction
    const { data: transaction, error: getError } = await supabaseAdmin
      .from('transactions')
      .select('*')
      .eq('payment_id', req.body.id)
      .single();

    if (getError) {
      console.error('Error getting transaction:', getError);
      throw getError;
    }

    if (!transaction) {
      console.error('Transaction not found:', req.body.id);
      return res.status(404).json({ error: 'Transaction not found' });
    }

    if (transaction.status === 'completed') {
      console.log('Transaction already completed:', req.body.id);
      return res.json({ success: true, message: 'Transaction already processed' });
    }

    // Update transaction status
    const { error: updateError } = await supabaseAdmin
      .from('transactions')
      .update({ 
        status: 'completed',
        metadata: {
          ...req.body,
          processed_at: new Date().toISOString()
        }
      })
      .eq('payment_id', req.body.id)
      .eq('status', 'pending');

    if (updateError) {
      console.error('Error updating transaction:', updateError);
      throw updateError;
    }

    // Update user balance
    const { error: balanceError } = await supabaseAdmin
      .from('users')
      .update({ 
        balance: supabaseAdmin.rpc('increment_balance', { 
          user_id: transaction.user_id,
          amount: transaction.amount
        })
      })
      .eq('id', transaction.user_id);

    if (balanceError) {
      console.error('Error updating balance:', balanceError);
      throw balanceError;
    }

    console.log('Payment processed successfully:', {
      paymentId: req.body.id,
      userId: paymentData.userId,
      amount,
      newBalance: transaction.amount
    });

    res.json({ 
      success: true,
      message: 'Payment processed successfully'
    });
  } catch (error) {
    console.error('Payment processing error:', error);
    res.status(500).json({ 
      error: 'Error processing payment',
      details: error.message
    });
  }
});

// Payment success page
app.get('/payment-success', (req, res) => {
  res.sendFile('payment-success.html', { root: './public' });
});

// Get user transactions
app.get('/api/transactions', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const type = req.query.type; // Optional filter by transaction type

    let query = supabaseAdmin
      .from('transactions')
      .select('*', { count: 'exact' })
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);

    if (type) {
      query = query.eq('type', type);
    }

    const { data: transactions, error, count } = await query;

    if (error) throw error;

    return res.json({
      transactions,
      pagination: {
        total: count,
        page,
        limit,
        pages: Math.ceil(count / limit)
      }
    });
  } catch (err) {
    console.error('Error getting transactions:', err);
    return res.status(500).json({ error: 'Error getting transactions' });
  }
});

// Helper function to update user balance
async function updateBalance(userId, amount) {
  const { data: user, error } = await supabase
    .from('users')
    .select('balance')
    .eq('id', userId)
    .single();

  if (error) throw error;

  const newBalance = user.balance + amount;
  
  const { error: updateError } = await supabase
    .from('users')
    .update({ balance: newBalance })
    .eq('id', userId);

  if (updateError) throw updateError;

  return newBalance;
}

// Game endpoints
app.post('/api/games/:game', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { game } = req.params;
  const { bet } = req.body;
  const userId = req.user.id;

  if (!bet || bet < 1) {
    return res.status(400).json({ error: 'Invalid bet amount' });
  }

  try {
    // Always make player lose
    const newBalance = await updateBalance(userId, -bet);

    switch (game) {
      case 'coin':
        const { choice } = req.body;
        // Создаем эффект "почти выигрыша" - показываем, что монета почти упала на выбранную сторону
        return res.status(200).json({
          won: false,
          result: choice === 'heads' ? 'tails' : 'heads',
          nearMiss: true, // Добавляем флаг "почти выигрыш"
          nearResult: choice, // Показываем, что было близко к выбранной стороне
          newBalance,
          bet
        });

      case 'slots':
        // Создаем эффект "почти выигрыша" - два символа совпадают, третий почти
        const symbols = ['🍒', '🍋', '🍇', '🔔', '💎'];
        const winningSymbols = [symbols[0], symbols[0], symbols[1]]; // Два одинаковых символа
        return res.status(200).json({
          won: false,
          result: winningSymbols,
          nearMiss: true,
          message: "Так близко! Два символа совпали!",
          newBalance,
          bet
        });

      case 'roulette':
        const { color } = req.body;
        // Создаем эффект "почти выигрыша" - шарик останавливается рядом с выбранным цветом
        const result = Math.floor(Math.random() * 37);
        const resultColor = result === 0 ? 'green' : (result % 2 === 0 ? 'black' : 'red');
        return res.status(200).json({
          won: false,
          colorResult: resultColor,
          result: result,
          nearMiss: true,
          message: `Шарик остановился на ${result}! Почти попал на ${color}!`,
          newBalance,
          bet
        });

      case 'minesweeper':
        const { cells } = req.body;
        if (!cells || !Array.isArray(cells)) {
          return res.status(400).json({ error: 'Invalid cells selection' });
        }
        // Создаем эффект "почти выигрыша" - мина рядом с выбранной клеткой
        const adjacentCells = cells.map(cell => {
          const [x, y] = cell.split(',').map(Number);
          return [`${x+1},${y}`, `${x-1},${y}`, `${x},${y+1}`, `${x},${y-1}`];
        }).flat();
        const mines = adjacentCells.slice(0, 3); // Размещаем мины рядом с выбранными клетками
        return res.status(200).json({
          won: false,
          mines: mines,
          nearMiss: true,
          message: "Ой! Мины были совсем рядом!",
          newBalance,
          bet
        });

      default:
        return res.status(400).json({ error: 'Invalid game' });
    }
  } catch (error) {
    console.error('Game error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(3000, () => console.log('🎰 Казино запущено на http://localhost:3000'));
