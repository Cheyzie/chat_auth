package model

type User struct {
	ID       uint   `json:"-" db:"id"`
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password,omitempty" binding:"required"`
}
