import { createClient } from '@supabase/supabase-js';
import cookie from 'cookie';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Получаем userId из cookie
  const cookies = cookie.parse(req.headers.cookie || '');
  const auth = cookies.auth ? JSON.parse(cookies.auth) : null;
  const userId = auth?.id;

  const { bet } = req.body;

  if (!userId || !bet || bet < 1) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  try {
    // Get current balance
    const { data: user, error } = await supabase
      .from('users')
      .select('balance')
      .eq('id', userId)
      .single();

    if (error) throw error;

    // Всегда забираем ставку
    const newBalance = user.balance - bet;
    
    // Update balance
    const { error: updateError } = await supabase
      .from('users')
      .update({ balance: newBalance })
      .eq('id', userId);

    if (updateError) throw updateError;

    // Всегда показываем почти выигрышную комбинацию
    const reels = ['🍒', '🍋', '🍇', '🔔', '💎'];
    const result = [
      reels[Math.floor(Math.random() * reels.length)],
      reels[Math.floor(Math.random() * reels.length)],
      reels[Math.floor(Math.random() * reels.length)]
    ];

    // Проверяем, не выпала ли случайно выигрышная комбинация
    const isWin = result[0] === result[1] && result[1] === result[2];
    if (isWin) {
      // Если случайно выпала выигрышная комбинация, меняем один символ
      const differentSymbols = reels.filter(symbol => symbol !== result[0]);
      result[2] = differentSymbols[Math.floor(Math.random() * differentSymbols.length)];
    }

    // Record transaction
    const { error: transactionError } = await supabase
      .from('transactions')
      .insert([{
        user_id: userId,
        type: 'game_loss',
        amount: bet,
        game_type: 'slots',
        metadata: {
          result,
          nearWin: true
        }
      }]);

    if (transactionError) throw transactionError;

    return res.status(200).json({
      won: false,
      result,
      newBalance,
      bet,
      nearWin: true // Всегда показываем, что было близко к выигрышу
    });
  } catch (error) {
    console.error('Slots game error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
} 