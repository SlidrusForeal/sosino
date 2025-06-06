-- Add minecraft_uuid column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS minecraft_uuid TEXT;

-- Create index for minecraft_uuid
CREATE INDEX IF NOT EXISTS idx_users_minecraft_uuid ON users(minecraft_uuid);

-- Add payment_id column to transactions table
ALTER TABLE transactions 
ADD COLUMN IF NOT EXISTS payment_id TEXT UNIQUE;

-- Create index for payment_id
CREATE INDEX IF NOT EXISTS idx_transactions_payment_id ON transactions(payment_id);

-- Add status column if it doesn't exist
ALTER TABLE transactions 
ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending';

-- Add metadata column if it doesn't exist
ALTER TABLE transactions 
ADD COLUMN IF NOT EXISTS metadata JSONB;

-- Drop existing policies if they exist
DROP POLICY IF EXISTS "Users can view their own data" ON users;
DROP POLICY IF EXISTS "Users can view their own transactions" ON transactions;
DROP POLICY IF EXISTS "Users can view their own game history" ON game_history;

-- Recreate RLS policies
CREATE POLICY "Users can view their own data" ON users
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can view their own transactions" ON transactions
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can view their own game history" ON game_history
    FOR SELECT USING (auth.uid() = user_id);

-- Drop existing functions if they exist
DROP FUNCTION IF EXISTS update_balance CASCADE;
DROP FUNCTION IF EXISTS update_updated_at_column CASCADE;

-- Recreate functions
CREATE OR REPLACE FUNCTION update_balance()
RETURNS TRIGGER AS $$
BEGIN
    -- Only update balance for completed transactions
    IF NEW.status = 'completed' THEN
        IF NEW.type = 'deposit' OR NEW.type = 'game_win' THEN
            UPDATE users 
            SET balance = balance + NEW.amount,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = NEW.user_id;
        ELSIF NEW.type = 'withdraw' OR NEW.type = 'game_loss' THEN
            UPDATE users 
            SET balance = balance - NEW.amount,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = NEW.user_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Drop existing triggers if they exist
DROP TRIGGER IF EXISTS update_balance_trigger ON transactions;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;

-- Recreate triggers
CREATE TRIGGER update_balance_trigger
    AFTER INSERT OR UPDATE ON transactions
    FOR EACH ROW
    EXECUTE FUNCTION update_balance();

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column(); 