package services

import (
	"context"
	"github.com/Marmotte-40K/backend-owasp/models"
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

	err := s.db.QueryRow(ctx, "SELECT id, name, surname, password, email FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Name, &user.Surname, &user.Password, &user.Email)
	if err != nil {
		return nil, err
	}
	return &user, nil

}

func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User

	err := s.db.QueryRow(ctx, "SELECT id, name, surname, password, email FROM users WHERE email = $1", email).Scan(&user.ID, &user.Name, &user.Surname, &user.Password, &user.Email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserService) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	var userNew models.User

	err := s.db.QueryRow(ctx, "INSERT INTO users (name, surname, password, email) VALUES ($1, $2, $3, $4) RETURNING id, name, email", user.Name, user.Surname, user.Password, user.Email).Scan(&userNew.ID, &userNew.Name, &userNew.Email)
	if err != nil {
		return nil, err
	}

	return &userNew, nil
}
