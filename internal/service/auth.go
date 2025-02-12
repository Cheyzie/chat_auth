package service

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/Cheyzie/chat_auth/internal/model"
	"github.com/golang-jwt/jwt/v5"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"

type UserRepository interface {
	Create(user model.User) (uint, error)
	GetByID(id uint) (model.User, error)
	GetByEmail(email string) (model.User, error)
	GetByCredentials(email, password_hash string) (model.User, error)
}

type RefreshTokenRepository interface {
	Store(ctx context.Context, token *model.RefreshToken) error
	Get(ctx context.Context, token string) (*model.RefreshToken, error)
	ListByUserID(ctx context.Context, userID uint) ([]*model.RefreshToken, error)
	Delete(ctx context.Context, userID, tokenID uint) error
}

type tokenClaims struct {
	jwt.RegisteredClaims
	UserId uint
}

type AuthorizationService struct {
	repo       UserRepository
	rtRepo     RefreshTokenRepository
	salt       string
	signingKey string
	token_ttl  time.Duration
}

func NewAuthorizationService(repo UserRepository, rtRepo RefreshTokenRepository) *AuthorizationService {
	return &AuthorizationService{
		repo:       repo,
		rtRepo:     rtRepo,
		salt:       os.Getenv("HASH_SALT"),
		signingKey: os.Getenv("JWT_SIGNING_KEY"),
		token_ttl:  2 * time.Minute,
	}
}

func (s *AuthorizationService) CreateUser(user model.User) (uint, error) {
	user.Password = s.generatePasswordHahs(user.Password)
	return s.repo.Create(user)
}

func (s *AuthorizationService) GenerateToken(email, password, sessionName string) (model.Token, error) {

	user, err := s.repo.GetByCredentials(email, s.generatePasswordHahs(password))
	if err != nil {
		return model.Token{}, err
	}

	return s.generateToken(user.ID, sessionName)
}

func (s *AuthorizationService) ListUserSessions(userID uint) ([]*model.RefreshToken, error) {
	return s.rtRepo.ListByUserID(context.Background(), userID)
}

func (s *AuthorizationService) RefreshToken(refresh_token string) (model.Token, error) {
	ctx := context.Background()

	refreshToken, err := s.rtRepo.Get(ctx, refresh_token)
	if err != nil {
		return model.Token{}, err
	}

	return s.generateToken(refreshToken.UserID, refreshToken.SessionName)
}

func randStringBytesRmndr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func (s *AuthorizationService) generateToken(userID uint, sessionName string) (model.Token, error) {
	ctx := context.Background()
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.token_ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		userID,
	}).SignedString([]byte(s.signingKey))

	if err != nil {
		return model.Token{}, err
	}

	refreshToken := model.RefreshToken{
		Token:       randStringBytesRmndr(64),
		UserID:      userID,
		SessionName: sessionName,
		ExpiresAt:   time.Now().Add(time.Hour * 24 * 7),
	}

	if err := s.rtRepo.Store(ctx, &refreshToken); err != nil {
		return model.Token{}, err
	}

	return model.Token{AccessToken: accessToken, RefreshToken: refreshToken.Token}, err
}

func (s *AuthorizationService) generatePasswordHahs(passwor string) string {
	hash := sha1.New()
	hash.Write([]byte(passwor))

	return fmt.Sprintf("%x", hash.Sum([]byte(s.salt)))
}

func (s *AuthorizationService) ParseToken(access_token string) (uint, error) {
	token, err := jwt.ParseWithClaims(access_token, &tokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(s.signingKey), nil
	})
	if err != nil {
		return 0, err
	}
	claims, ok := token.Claims.(*tokenClaims)
	if !ok {
		return 0, errors.New("token claims not of type *tokenClaims")
	}
	return claims.UserId, nil
}

func (s *AuthorizationService) GetByID(id uint) (model.User, error) {
	user, err := s.repo.GetByID(id)

	if err != nil {
		return user, fmt.Errorf("get user by id=%d error: %w", id, err)
	}

	return user, nil
}

func (s *AuthorizationService) DropSession(userID, sessionID uint) error {
	ctx := context.Background()

	err := s.rtRepo.Delete(ctx, userID, sessionID)

	if err != nil {
		return err
	}
	return nil
}
