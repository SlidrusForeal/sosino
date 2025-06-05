const express = require('express');
const session = require('express-session');
const cookie = require('cookie-parser');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const { getUser, getBalance, transfer } = require('./spworlds');
const app = express();

app.use(express.static('public'));
app.use(express.json());
app.use(session({
  secret: 'ae9a373c35ca68721deb2bd376d28e464290cb08174d665a6500f10cc5740e9e75ab438c873749cfd5d99ee1bb4f079c14c28b4efb1ee39a8b84014901d861ae25fda3895b7ec5aea85a33ca6da7426df7b0d747fc28b1f447f748238e60c3d2f1bdc30258e027b67fefaf5ac4540dd949e09674dc6e0fc4d6c5a801db3650bb',
  resave: false,
  saveUninitialized: false
}));
app.use(cookie());
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

passport.use(new DiscordStrategy({
  clientID: 'YOUR_CLIENT_ID',
  clientSecret: 'YOUR_CLIENT_SECRET',
  callbackURL: 'http://localhost:3000/auth/discord/callback',
  scope: ['identify']
}, (accessToken, refreshToken, profile, done) => {
  process.nextTick(() => done(null, profile));
}));


app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

app.get('/api/auth/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json(req.user);
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

const OWNER = 'Sosmark'; // Замените на свой ник
const MIN = 1;
const MAX = 64;
const MULTIPLIER = 60;

app.post('/api/play', async (req, res) => {
  const token = req.cookies.token;
  const number = parseInt(req.body.number);

  if (!token || isNaN(number) || number < MIN || number > MAX) {
    return res.status(400).json({ error: 'Неверные данные' });
  }

  try {
    const user = await getUser(token);
    const balance = await getBalance(user.username);
    const bet = 1;

    if (balance < bet) return res.status(403).json({ error: 'Недостаточно руды' });

    const result = Math.floor(Math.random() * MAX) + 1;
    const won = result === number;

    await transfer(token, OWNER, bet);

    if (won) await transfer(null, user.username, bet * MULTIPLIER);

    res.json({ result, won });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка сервера', detail: e.message });
  }
});

app.post('/api/play/coin', async (req, res) => {
  const token = req.cookies.token;
  const { choice } = req.body;
  const user = await getUser(token);
  const bet = 1;

  const nearMiss = choice === 'heads' ? 'heads' : 'tails';
  const finalResult = choice === 'heads' ? 'tails' : 'heads';

  await transfer(token, OWNER, bet);
  logGame(user.username, 'coin', false);

  res.json({ result: finalResult, near: nearMiss, won: false });
});


app.post('/api/slots', async (req, res) => {
  const token = req.cookies.token;
  const user = await getUser(token);
  const bet = 1;
  const reels = ['🍒', '🍋', '🍇', '🔔', '💎'];

  const symbol = reels[Math.floor(Math.random() * reels.length)];
  const result = Math.random() < 0.5
    ? [symbol, symbol, pickOther(symbol)]
    : [pickOther(symbol), symbol, symbol];

  function pickOther(sym) {
    const pool = reels.filter(s => s !== sym);
    return pool[Math.floor(Math.random() * pool.length)];
  }

  await transfer(token, OWNER, bet);
  logGame(user.username, 'slots', false);
  res.json({ result, won: false });
});



app.post('/api/roulette', async (req, res) => {
  const token = req.cookies.token;
  const user = await getUser(token);
  const color = req.body.color; // 'red' или 'black'
  const bet = 1;

  const fakeColor = color === 'red' ? 'black' : 'red'; // Проигрыш
  await transfer(token, OWNER, bet);
  logGame(user.username, 'roulette', false);
  res.json({ result: Math.floor(Math.random() * 37), colorResult: fakeColor, won: false });
});


app.post('/api/minesweeper', async (req, res) => {
  const { cells } = req.body;
  const token = req.cookies.token;
  const user = await getUser(token);
  const bet = 1;

  const hit = true;
  const mines = [...cells];

  await transfer(token, OWNER, bet);
  logGame(user.username, 'minesweeper', false);
  res.json({ mines, hit, won: false });
});


app.get('/api/admin/stats', async (req, res) => {
  const log = JSON.parse(fs.readFileSync('./log.json'));
  const players = new Set(log.map(e => e.username)).size;
  const totalGames = log.length;
  const wins = log.filter(e => e.won).length;
  const losses = totalGames - wins;
  res.json({ players, totalGames, wins, losses });
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
    .map(([username, { wins, games }]) => ({ username, winrate: (wins / games * 100).toFixed(1) }))
    .sort((a, b) => b.winrate - a.winrate);
  res.json(rating);
});

function logGame(username, game, won) {
  const log = fs.existsSync('./log.json')
    ? JSON.parse(fs.readFileSync('./log.json'))
    : [];
  log.push({ time: new Date().toISOString(), username, game, won });
  fs.writeFileSync('./log.json', JSON.stringify(log, null, 2));
}


app.listen(3000, () => console.log('🎰 Казино запущено на http://localhost:3000'));
