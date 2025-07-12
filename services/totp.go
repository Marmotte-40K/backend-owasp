package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image/png"
	"os"

	"github.com/Marmotte-40K/backend-owasp/models"
	"github.com/Marmotte-40K/backend-owasp/pkg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type TOTPService struct {
	db *pgxpool.Pool
}

func NewTOTPService(db *pgxpool.Pool) *TOTPService {
	return &TOTPService{db: db}
}

func (s *TOTPService) SaveEncryptedTOTPSecret(userID int, secret string) error {
	encrypted, err := pkg.Encrypt([]byte(secret), []byte(os.Getenv("ENCRYPTION_KEY")))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		context.Background(),
		"UPDATE users SET totp_secret=$1 WHERE id=$2",
		encrypted, userID,
	)
	return err
}

func (s *TOTPService) LoadDecryptedTOTPSecret(userID int) (string, error) {
	var encrypted string
	err := s.db.QueryRow(
		context.Background(),
		"SELECT totp_secret FROM users WHERE id=$1",
		userID,
	).Scan(&encrypted)
	if err != nil {
		return "", err
	}
	plaintext, err := pkg.Decrypt(encrypted, []byte(os.Getenv("ENCRYPTION_KEY")))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (s *TOTPService) GenerateQRCode(user *models.User, issuer string) (*models.TOTPResponse, error) {

	secret, err := pkg.Decrypt(user.TotpSecret, []byte(os.Getenv("ENCRYPTION_KEY")))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		issuer, user.Email, string(secret), issuer))
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	err = png.Encode(&buf, img)
	if err != nil {
		return nil, fmt.Errorf("failed to encode QR code: %w", err)
	}

	qrCodeDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	return &models.TOTPResponse{
		QRCode:         qrCodeDataURL,
		Secret:         string(secret),
		ManualEntryKey: string(secret),
	}, nil
}

func (s *TOTPService) ValidateCode(code, encryptedSecret string) bool {
	secret, err := pkg.Decrypt(encryptedSecret, []byte(os.Getenv("ENCRYPTION_KEY")))
	if err != nil {
		return false
	}
	return totp.Validate(code, string(secret))
}
