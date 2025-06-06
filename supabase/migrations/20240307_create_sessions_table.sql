-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index on expires_at for faster cleanup
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);

-- Create function to create sessions table
CREATE OR REPLACE FUNCTION create_sessions_table()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Create sessions table if it doesn't exist
    CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        session TEXT NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Create index if it doesn't exist
    IF NOT EXISTS (
        SELECT 1
        FROM pg_indexes
        WHERE tablename = 'sessions'
        AND indexname = 'sessions_expires_at_idx'
    ) THEN
        CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);
    END IF;
END;
$$;

-- Create function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
END;
$$;

-- Create a cron job to run cleanup every hour
SELECT cron.schedule(
    'cleanup-expired-sessions',
    '0 * * * *',  -- Every hour
    'SELECT cleanup_expired_sessions()'
); 