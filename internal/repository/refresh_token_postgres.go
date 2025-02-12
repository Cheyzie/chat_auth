package repository

import (
	"context"
	"fmt"

	"github.com/Cheyzie/chat_auth/internal/model"
	"github.com/Cheyzie/chat_auth/internal/service"
	"github.com/jmoiron/sqlx"
)

const (
	refreshTokenTable = "refresh_tokens"
)

type RefreshTokenPostgres struct {
	db *sqlx.DB
}

func NewRefreshTokenPostgres(db *sqlx.DB) service.RefreshTokenRepository {
	return &RefreshTokenPostgres{
		db: db,
	}
}

func (r *RefreshTokenPostgres) Store(ctx context.Context, token *model.RefreshToken) error {
	query := fmt.Sprintf("INSERT INTO %s (token, user_id, session_name, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, session_name) DO UPDATE SET token = EXCLUDED.token, expires_at = EXCLUDED.expires_at RETURNING id, created_at;", refreshTokenTable)
	row := r.db.QueryRow(query, token.Token, token.UserID, token.SessionName, token.ExpiresAt)

	if err := row.Scan(&token.ID, &token.CreatedAt); err != nil {
		return err
	}
	return nil
}

func (r *RefreshTokenPostgres) Get(ctx context.Context, token string) (*model.RefreshToken, error) {
	tokenEntity := new(model.RefreshToken)

	query := fmt.Sprintf("SELECT id, token, user_id, session_name, expires_at, created_at FROM %s WHERE token = $1;", refreshTokenTable)
	err := r.db.Get(tokenEntity, query, token)

	if err != nil {
		return nil, err
	}

	return tokenEntity, nil
}

func (r *RefreshTokenPostgres) ListByUserID(ctx context.Context, userID uint) ([]*model.RefreshToken, error) {
	tokenEntity := make([]*model.RefreshToken, 0, 1)

	query := fmt.Sprintf("SELECT id, user_id, session_name, expires_at, created_at FROM %s WHERE user_id = $1;", refreshTokenTable)
	err := r.db.Select(&tokenEntity, query, userID)

	if err != nil {
		return nil, err
	}

	return tokenEntity, nil
}

func (r *RefreshTokenPostgres) Delete(ctx context.Context, userID, tokenID uint) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE user_id = $1 AND id = $2;", refreshTokenTable)
	_, err := r.db.Exec(query, userID, tokenID)

	if err != nil {
		return err
	}

	return nil
}
