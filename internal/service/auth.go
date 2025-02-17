package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/Cheyzie/chat_auth/internal/model"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"

var ErrNotFound error = errors.New("not found")

type UserRepository interface {
	Store(user model.User) error
	GetByID(id uuid.UUID) (model.User, error)
	GetByEmail(email string) (model.User, error)
	GetByCredentials(email, password_hash string) (model.User, error)
}

type RefreshTokenRepository interface {
	Store(ctx context.Context, token *model.RefreshToken) error
	Get(ctx context.Context, token string) (*model.RefreshToken, error)
	GetBySessionID(ctx context.Context, id uuid.UUID) (*model.RefreshToken, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*model.RefreshToken, error)
	Delete(ctx context.Context, userID, tokenID uuid.UUID) error
}

type tokenClaims struct {
	jwt.RegisteredClaims
	UserId    uuid.UUID
	SessionID uuid.UUID
}

type AuthorizationService struct {
	repo       UserRepository
	rtRepo     RefreshTokenRepository
	salt       string
	privateKey string
	publicKey  string
	token_ttl  time.Duration
}

func NewAuthorizationService(repo UserRepository, rtRepo RefreshTokenRepository) *AuthorizationService {
	return &AuthorizationService{
		repo:       repo,
		rtRepo:     rtRepo,
		salt:       os.Getenv("HASH_SALT"),
		privateKey: os.Getenv("JWT_PRIVATE_KEY"),
		publicKey:  os.Getenv("JWT_PUBLIC_KEY"),
		token_ttl:  5 * time.Minute,
	}
}

func (s *AuthorizationService) CreateUser(user model.User) (uuid.UUID, error) {
	op := "[AuthorizationService.CreateUser]"
	user.Password = s.generatePasswordHahs(user.Password)
	user.ID = uuid.New()
	if err := s.repo.Store(user); err != nil {
		return uuid.Nil, fmt.Errorf("%s repo invocation error: %w", op, err)
	}
	return user.ID, nil
}

func (s *AuthorizationService) GenerateToken(email, password, sessionName string) (model.Token, error) {

	user, err := s.repo.GetByCredentials(email, s.generatePasswordHahs(password))
	if err != nil {
		return model.Token{}, err
	}

	return s.generateToken(user.ID, sessionName)
}

func (s *AuthorizationService) ListUserSessions(userID uuid.UUID) ([]*model.RefreshToken, error) {
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

func (s *AuthorizationService) generateToken(userID uuid.UUID, sessionName string) (model.Token, error) {
	ctx := context.Background()
	refreshToken := model.RefreshToken{
		ID:          uuid.New(),
		Token:       randStringBytesRmndr(64),
		UserID:      userID,
		SessionName: sessionName,
		ExpiresAt:   time.Now().Add(time.Hour * 24 * 7),
		CreatedAt:   time.Now(),
	}

	if err := s.rtRepo.Store(ctx, &refreshToken); err != nil {
		return model.Token{}, err
	}

	blockPriv, _ := pem.Decode([]byte(s.privateKey))
	if blockPriv == nil {
		return model.Token{}, errors.New("cant parse private token")
	}

	x509EncodedPriv := blockPriv.Bytes

	privateKey, err := x509.ParseECPrivateKey(x509EncodedPriv)
	if err != nil {
		return model.Token{}, err
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, tokenClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.token_ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		userID,
		refreshToken.ID,
	}).SignedString(privateKey)

	if err != nil {
		return model.Token{}, err
	}

	return model.Token{AccessToken: accessToken, RefreshToken: refreshToken.Token}, err
}

func (s *AuthorizationService) generatePasswordHahs(passwor string) string {
	hash := sha1.New()
	hash.Write([]byte(passwor))

	return fmt.Sprintf("%x", hash.Sum([]byte(s.salt)))
}

func (s *AuthorizationService) ParseToken(access_token string) (*tokenClaims, error) {
	blockPub, _ := pem.Decode([]byte(s.publicKey))
	if blockPub == nil {
		return nil, errors.New("cant parse public token")
	}
	x509EncodedPub := blockPub.Bytes

	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, err
	}
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	token, err := jwt.ParseWithClaims(access_token, &tokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, errors.New("invalid signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*tokenClaims)
	if !ok {
		return nil, errors.New("token claims not of type *tokenClaims")
	}
	return claims, nil
}

func (s *AuthorizationService) GetByID(id uuid.UUID) (model.User, error) {
	user, err := s.repo.GetByID(id)

	if err != nil {
		return user, fmt.Errorf("get user by id=%d error: %w", id, err)
	}

	return user, nil
}

func (s *AuthorizationService) FindSession(ctx context.Context, id uuid.UUID) (*model.RefreshToken, error) {
	session, err := s.rtRepo.GetBySessionID(ctx, id)

	if err != nil {
		return session, fmt.Errorf("get session by id=%d error: %w", id, err)
	}

	return session, nil
}

func (s *AuthorizationService) DropSession(userID, sessionID uuid.UUID) error {
	ctx := context.Background()

	err := s.rtRepo.Delete(ctx, userID, sessionID)

	if err != nil {
		return err
	}
	return nil
}
