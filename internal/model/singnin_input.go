package model

type SigninInput struct {
	Email       string `json:"email" binding:"required"`
	Password    string `json:"password" binding:"required"`
	SessionName string `json:"session_name" binding:"required"`
}
