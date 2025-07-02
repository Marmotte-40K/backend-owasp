package services

import (
	"context"
	"fmt"

	"github.com/Marmotte-40K/backend-owasp/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserService struct {
	db *pgxpool.Pool
}

func NewUserService(db *pgxpool.Pool) *UserService {
	return &UserService{
		db: db,
	}
}

func (s *UserService) GetUserByID(ctx context.Context, userID int64) (*models.User, error) {
	var user models.User

	err := s.db.QueryRow(ctx, "SELECT id, username, email FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Username, &user.Email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user with ID %d not found", userID)
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil

}

func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User

	err := s.db.QueryRow(ctx, "SELECT id, username, email FROM users WHERE email = $1", email).Scan(&user.ID, &user.Username, &user.Email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user with email %s not found", email)
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil
}

func (s *UserService) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	var userNew models.User

	err := s.db.QueryRow(ctx, "INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id, username, email", user.Username, user.Email).Scan(&userNew.ID, &userNew.Username, &userNew.Email)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	return &userNew, nil
}
