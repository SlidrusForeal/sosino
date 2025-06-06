import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl || !supabaseAnonKey || !supabaseServiceKey) {
  throw new Error('Missing Supabase environment variables');
}

// Create Supabase client with anonymous key for client-side operations
export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: false
  },
  global: {
    headers: {
      'x-application-name': 'casino-sosmark'
    }
  }
});

// Create Supabase client with service role key for server-side operations
export const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    persistSession: false
  },
  global: {
    headers: {
      'x-application-name': 'casino-sosmark'
    }
  }
});

// Helper function to retry failed operations
const retryOperation = async (operation, maxRetries = 3, delay = 1000) => {
  let lastError;
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      console.error(`Attempt ${i + 1} failed:`, error.message);
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, delay * (i + 1)));
      }
    }
  }
  throw lastError;
};

// User management functions
export const getUser = async (discordId) => {
  return retryOperation(async () => {
    const { data, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('discord_id', discordId)
      .single();

    if (error) {
      console.error('Error getting user:', error);
      throw error;
    }
    return data;
  });
};

export const createUser = async (discordId, discordUsername, minecraftUsername) => {
  return retryOperation(async () => {
    const { data, error } = await supabaseAdmin
      .from('users')
      .insert([
        {
          discord_id: discordId,
          discord_username: discordUsername,
          minecraft_username: minecraftUsername
        }
      ])
      .select()
      .single();

    if (error) {
      console.error('Error creating user:', error);
      throw error;
    }
    return data;
  });
};

// Transaction functions
export const createTransaction = async (userId, type, amount, gameType = null) => {
  return retryOperation(async () => {
    const { data, error } = await supabaseAdmin
      .from('transactions')
      .insert([
        {
          user_id: userId,
          type,
          amount,
          game_type: gameType
        }
      ])
      .select()
      .single();

    if (error) {
      console.error('Error creating transaction:', error);
      throw error;
    }
    return data;
  });
};

// Game history functions
export const createGameHistory = async (userId, gameType, betAmount, winAmount, result) => {
  return retryOperation(async () => {
    const { data, error } = await supabaseAdmin
      .from('game_history')
      .insert([
        {
          user_id: userId,
          game_type: gameType,
          bet_amount: betAmount,
          win_amount: winAmount,
          result
        }
      ])
      .select()
      .single();

    if (error) {
      console.error('Error creating game history:', error);
      throw error;
    }
    return data;
  });
};

// Balance functions
export const getBalance = async (userId) => {
  return retryOperation(async () => {
    const { data, error } = await supabaseAdmin
      .from('users')
      .select('balance')
      .eq('id', userId)
      .single();

    if (error) {
      console.error('Error getting balance:', error);
      throw error;
    }
    return data.balance;
  });
};

// Statistics functions
export const getUserStats = async (userId) => {
  return retryOperation(async () => {
    const { data, error } = await supabaseAdmin
      .from('game_history')
      .select('*')
      .eq('user_id', userId);

    if (error) {
      console.error('Error getting user stats:', error);
      throw error;
    }
    return data;
  });
};

export const getGlobalStats = async () => {
  return retryOperation(async () => {
    const { data, error } = await supabaseAdmin
      .from('game_history')
      .select('*');

    if (error) {
      console.error('Error getting global stats:', error);
      throw error;
    }
    return data;
  });
}; 