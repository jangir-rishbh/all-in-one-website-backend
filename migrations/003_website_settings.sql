CREATE TABLE IF NOT EXISTS website_settings (
    id smallint PRIMARY KEY DEFAULT 1,
    name text,
    logo_url text,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT single_row CHECK (id = 1)
);

-- Insert a default row if it doesn't exist
INSERT INTO website_settings (id, name, logo_url)
VALUES (1, 'Ma Baba Cloth Store', '')
ON CONFLICT (id) DO NOTHING;
