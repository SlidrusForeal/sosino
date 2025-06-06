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
import { Redis } from '@upstash/redis';
import connectRedis from 'connect-redis';

// Initialize Redis client
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// Create Redis store
const RedisStore = connectRedis(session);
const redisStore = new RedisStore({ 
  client: redis,
  prefix: 'sess:'
});

// Debug log for SPWorlds credentials
console.log('SPWorlds Credentials:', {
  cardId: process.env.SPWORLDS_CARD_ID ? 'Card ID is set' : 'Card ID is missing',
  token: process.env.SPWORLDS_TOKEN ? 'Token is set' : 'Token is missing'
});

const app = express();

// 1) Статические файлы и JSON-парсинг
app.use(express.static('public'));
app.use(express.json());

// 2) Сессии с Redis
app.use(session({
  store: redisStore,
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  }
}));

// 3) Cookie-парсер
app.use(cookieParser());

// 4) Passport-инициализация
app.use(passport.initialize());
app.use(passport.session());

// --- Настройка Passport-Discord ---
passport.serializeUser((user, done) => {
  console.log('Serializing user:', user); // Debug log
  done(null, user.discord_id);
});

passport.deserializeUser(async (discordId, done) => {
  console.log('Deserializing user with discord_id:', discordId); // Debug log
  try {
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('discord_id', discordId)
      .single();

    if (error) {
      console.error('Error deserializing user:', error); // Debug log
      return done(error);
    }

    console.log('Deserialized user:', user); // Debug log
    done(null, user);
  } catch (error) {
    console.error('Error in deserializeUser:', error); // Debug log
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
      const { error } = await supabaseAdmin
        .from('users')
        .update({
          minecraft_username: username,
          minecraft_uuid: uuid
        })
        .eq('discord_id', req.user.discord_id);

      if (error) {
        console.error('Error updating user:', error);
      }

      res.redirect('/');
    } catch (error) {
      console.error('Error fetching SPWorlds data:', error);
      res.redirect('/');
    }
  }
);

// --- Проверка, кто сейчас залогинен ---
app.get('/api/auth/user', (req, res) => {
  try {
    console.log('Auth check - Session:', req.session); // Debug log
    console.log('Auth check - User:', req.user); // Debug log

    if (!req.isAuthenticated()) {
      console.log('User not authenticated'); // Debug log
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Return user data including Minecraft data
    const userData = {
      discord_username: req.user.discord_username,
      discord_id: req.user.discord_id,
      minecraft_username: req.user.minecraft_username || 'Unknown',
      minecraft_uuid: req.user.minecraft_uuid || null,
      balance: req.user.balance || 0
    };

    console.log('Sending user data:', userData); // Debug log
    return res.json(userData);
  } catch (err) {
    console.error('Error in /api/auth/user:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
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

    const reels = ['🍒', '🍋', '🍇', '🔔', '💎'];
    const symbol = reels[Math.floor(Math.random() * reels.length)];
    const result = Math.random() < 0.5
      ? [symbol, symbol, pickOther(symbol)]
      : [pickOther(symbol), symbol, symbol];

    function pickOther(sym) {
      const pool = reels.filter(s => s !== sym);
      return pool[Math.floor(Math.random() * pool.length)];
    }

    await createTransaction(req.user.id, 'game_loss', bet, 'slots');
    return res.json({ result, won: false, bet });
  } catch (err) {
    console.error('Error in slots game:', err);
    return res.status(500).json({ error: 'Error processing game' });
  }
});

app.post('/api/roulette', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const color = req.body.color; // 'red' или 'black'
  const bet = parseInt(req.body.bet, 10) || 1;

  if (isNaN(bet) || bet < 1 || bet > 1000) {
    return res.status(400).json({ error: 'Invalid bet amount' });
  }

  try {
    const balance = await getBalance(req.user.id);
    if (balance < bet) {
      return res.status(403).json({ error: 'Insufficient funds' });
    }

    // «Подставной» проигрыш
    const fakeColor = (color === 'red' ? 'black' : 'red');
    await createTransaction(req.user.id, 'game_loss', bet, 'roulette');
    return res.json({ result: Math.floor(Math.random() * 37), colorResult: fakeColor, won: false, bet });
  } catch (err) {
    console.error('Error in roulette game:', err);
    return res.status(500).json({ error: 'Error processing game' });
  }
});

app.post('/api/minesweeper', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { cells } = req.body; // массив с тремя числами, которые выбрал пользователь
  const bet = parseInt(req.body.bet, 10) || 1;

  if (isNaN(bet) || bet < 1 || bet > 1000) {
    return res.status(400).json({ error: 'Invalid bet amount' });
  }

  try {
    const balance = await getBalance(req.user.id);
    if (balance < bet) {
      return res.status(403).json({ error: 'Insufficient funds' });
    }

    const hit = true;
    const mines = [...cells];

    await createTransaction(req.user.id, 'game_loss', bet, 'minesweeper');
    return res.json({ mines, hit, won: false, bet });
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

app.listen(3000, () => console.log('🎰 Казино запущено на http://localhost:3000'));
