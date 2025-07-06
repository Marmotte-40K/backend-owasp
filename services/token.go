package services

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type TokenService struct {
	db *pgxpool.Pool
}

func NewTokenService(db *pgxpool.Pool) *TokenService {
	return &TokenService{
		db: db,
	}
}

func (s *TokenService) AddRefreshToken(ctx context.Context, userId int, token string, exp time.Time) error {
	_, err := s.db.Exec(ctx, "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)", userId, token, exp)
	if err != nil {
		return err
	}
	return nil
}

func (s *TokenService) RemoveRefreshToken(ctx context.Context, userId int) error {
	_, err := s.db.Exec(ctx, "DELETE FROM refresh_tokens WHERE user_id = $1", userId)
	if err != nil {
		return err
	}
	return nil
}
