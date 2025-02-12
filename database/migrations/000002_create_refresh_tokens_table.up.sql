CREATE TABLE refresh_tokens
(
    id SERIAL PRIMARY KEY,
    token VARCHAR(64) NOT NULL,
    user_id INT UNIQUE NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_name varchar(18) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, session_name)
);