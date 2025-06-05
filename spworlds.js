const axios = require('axios');

const BASE = 'https://spworlds.ru/api';

module.exports = {
  getUser: async (token) => {
    const res = await axios.get(`${BASE}/auth/user`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return res.data;
  },

  getBalance: async (username) => {
    const res = await axios.get(`${BASE}/currency/balance/${username}`);
    return res.data?.balance ?? 0;
  },

  transfer: async (fromToken, toUsername, amount) => {
    const res = await axios.post(`${BASE}/currency/transfer`, {
      to: toUsername,
      amount,
      currency: 'diamond_ore'
    }, {
      headers: { Authorization: `Bearer ${fromToken}` }
    });
    return res.data;
  }
};
