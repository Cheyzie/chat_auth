package model

import "github.com/google/uuid"

type User struct {
	ID       uuid.UUID `json:"id" db:"id"`
	Username string    `json:"username" binding:"required"`
	Email    string    `json:"email" binding:"required"`
	Password string    `json:"password,omitempty" binding:"required"`
}
