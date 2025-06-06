const axios = require('axios');
const BASE = 'https://spworlds.ru/api';

// Токен твоего сервера/бота SPWorlds (чтобы можно было переводить игроку или списывать с игрока)
const SERVER_TOKEN = process.env.SPWORLDS_TOKEN;

module.exports = {
  // 1) Получить данные пользователя (username, id и т.д.) по его токену
  getUser: async (token) => {
    const res = await axios.get(`${BASE}/auth/user`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return res.data;
  },

  // 2) Получить баланс (в «рудах») у пользователя по нику
  getBalance: async (username) => {
    const res = await axios.get(`${BASE}/currency/balance/${username}`);
    return res.data?.balance ?? 0;
  },

  // 3) Перевод валюты «diamond_ore» между аккаунтами
  //    Если fromToken указан — перевод от этого аккаунта. Если null, то перевод от SERVER_TOKEN.
  //    toUsername — ник, amount — сколько «руды» переводим.
  transfer: async (fromToken, toUsername, amount) => {
    const tokenToUse = fromToken || SERVER_TOKEN;
    const res = await axios.post(`${BASE}/currency/transfer`, {
      to: toUsername,
      amount,
      currency: 'diamond_ore'
    }, {
      headers: { Authorization: `Bearer ${tokenToUse}` }
    });
    return res.data;
  }
};
