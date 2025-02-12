package repository

import (
	"fmt"

	"github.com/Cheyzie/chat_auth/internal/model"
	"github.com/Cheyzie/chat_auth/internal/service"
	"github.com/jmoiron/sqlx"
)

type UserPostgres struct {
	db *sqlx.DB
}

func NewUserPostgres(db *sqlx.DB) service.UserRepository {
	return &UserPostgres{db: db}
}

func (r *UserPostgres) GetByEmail(email string) (model.User, error) {
	var user model.User
	query := fmt.Sprintf("SELECT user.id, user.username, user.email FROM %s user WHERE user.id = $1;", usersTable)
	err := r.db.Get(&user, query, email)

	return user, err
}

func (r *UserPostgres) GetByCredentials(email, password_hash string) (model.User, error) {
	var user model.User
	query := fmt.Sprintf("SELECT id, username, email FROM %s WHERE email = $1 AND password_hash =$2;", usersTable)
	err := r.db.Get(&user, query, email, password_hash)

	return user, err
}

func (r *UserPostgres) GetByID(id uint) (model.User, error) {
	var user model.User
	query := fmt.Sprintf("SELECT id, username, email FROM %s WHERE id = $1;", usersTable)
	err := r.db.Get(&user, query, id)

	return user, err
}

func (r *UserPostgres) Create(user model.User) (uint, error) {
	var id uint

	query := fmt.Sprintf("INSERT INTO %s (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id;", usersTable)
	row := r.db.QueryRow(query, user.Username, user.Email, user.Password)

	if err := row.Scan(&id); err != nil {
		return 0, err
	}

	return id, nil
}
