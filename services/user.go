package services

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	mathRand "math/rand"
	"time"

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

	err := s.db.QueryRow(ctx, "SELECT id, name, surname, password, email, totp_secret, totp_enabled, failed_login_attempts, locked_until FROM users WHERE id = $1", userID).
		Scan(&user.ID, &user.Name, &user.Surname, &user.Password, &user.Email, &user.TotpSecret, &user.TotpEnabled, &user.FailedLoginAttempts, &user.LockedUntil)
	if err != nil {
		return nil, err
	}
	return &user, nil

}

func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User

	err := s.db.QueryRow(ctx, "SELECT id, name, surname, password, email, totp_secret, totp_enabled, failed_login_attempts, locked_until FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Name, &user.Surname, &user.Password, &user.Email, &user.TotpSecret, &user.TotpEnabled, &user.FailedLoginAttempts, &user.LockedUntil)
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

func (s *UserService) GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

func (s *UserService) UpdateTOTPEnabled(ctx context.Context, userID int64, enabled bool) error {
	_, err := s.db.Exec(ctx,
		"UPDATE users SET totp_enabled = $1 WHERE id = $2",
		enabled, userID)

	if err != nil {
		return fmt.Errorf("failed to update TOTP status: %w", err)
	}

	return nil
}

func (s *UserService) UpdateFailedAttemptsAndLock(ctx context.Context, userID int64, attempts int, lockUntil *time.Time) error {
	if lockUntil != nil {
		_, err := s.db.Exec(ctx,
			"UPDATE users SET failed_login_attempts=$1, locked_until=$2 WHERE id=$3",
			attempts, *lockUntil, userID)
		return err
	}
	_, err := s.db.Exec(ctx,
		"UPDATE users SET failed_login_attempts=$1, locked_until=NULL WHERE id=$2",
		attempts, userID)
	return err
}

func (s *UserService) UpdatePassword(ctx context.Context, userID int64, newPassword string) error {
	_, err := s.db.Exec(ctx,
		"UPDATE users SET password = $1 WHERE id = $2",
		newPassword, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	return nil
}

func (s *UserService) GenerateEmail2FACode(userID int64) (string, error) {
	code := fmt.Sprintf("%06d", mathRand.Intn(1000000))
	// mock: just print/log
	fmt.Printf("Mock email 2FA code for user %d: %s\n", userID, code)
	return code, nil
}
