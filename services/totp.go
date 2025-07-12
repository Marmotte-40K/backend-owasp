package services

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/Marmotte-40K/backend-owasp/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"image/png"
)

type TOTPService struct {
	db *pgxpool.Pool
}

func NewTOTPService(db *pgxpool.Pool) *TOTPService {
	return &TOTPService{db: db}
}

func (s *TOTPService) GenerateQRCode(user *models.User, issuer string) (*models.TOTPResponse, error) {

	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		issuer, user.Email, user.TotpSecret, issuer))
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
		Secret:         user.TotpSecret,
		ManualEntryKey: user.TotpSecret,
	}, nil
}

func (s *TOTPService) ValidateCode(code, secret string) bool {
	return totp.Validate(code, secret)
}
