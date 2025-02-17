package model

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Token       string    `json:"token,omitempty" db:"token"`
	UserID      uuid.UUID `json:"user_id" db:"user_id"`
	SessionName string    `json:"session_name" db:"session_name"`
	ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}
