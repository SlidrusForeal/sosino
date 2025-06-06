import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { bet, userId } = req.body;

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

    // Always make player lose
    const newBalance = user.balance - bet;
    
    // Update balance
    const { error: updateError } = await supabase
      .from('users')
      .update({ balance: newBalance })
      .eq('id', userId);

    if (updateError) throw updateError;

    // Always return losing combination
    return res.status(200).json({
      won: false,
      result: ['🍒', '🍋', '🍇'],
      newBalance,
      bet
    });
  } catch (error) {
    console.error('Slots game error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
} 