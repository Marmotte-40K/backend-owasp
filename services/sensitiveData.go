package services

import (
	"context"
	"os"

	"github.com/Marmotte-40K/backend-owasp/models"
	"github.com/Marmotte-40K/backend-owasp/pkg"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SensitiveDataService struct {
	db *pgxpool.Pool
}

func NewSensitiveDataService(db *pgxpool.Pool) *SensitiveDataService {
	return &SensitiveDataService{db: db}
}

func (s *SensitiveDataService) SaveOrUpdate(ctx context.Context, data *models.SensitiveData) error {
	var ibanEnc, fcEnc *string

	if data.IBAN != nil {
		enc, err := pkg.Encrypt([]byte(*data.IBAN), []byte(os.Getenv("ENCRYPTION_KEY_SENSITIVE_DATA")))
		if err != nil {
			return err
		}
		ibanEnc = &enc
	}
	if data.FiscalCode != nil {
		enc, err := pkg.Encrypt([]byte(*data.FiscalCode), []byte(os.Getenv("ENCRYPTION_KEY_SENSITIVE_DATA")))
		if err != nil {
			return err
		}
		fcEnc = &enc
	}

	query := "INSERT INTO sensitive_data (user_id, iban, fiscal_code) VALUES ($1, $2, $3) " +
		"ON CONFLICT (user_id) DO UPDATE SET " +
		"iban = COALESCE(EXCLUDED.iban, sensitive_data.iban), " +
		"fiscal_code = COALESCE(EXCLUDED.fiscal_code, sensitive_data.fiscal_code)"

	_, err := s.db.Exec(ctx, query, data.UserID, ibanEnc, fcEnc)
	return err
}

func (s *SensitiveDataService) GetByUserID(ctx context.Context, userID int64) (*models.SensitiveData, error) {
	var data models.SensitiveData
	var ibanEnc, cfEnc string
	err := s.db.QueryRow(ctx, "SELECT id, iban, fiscal_code FROM sensitive_data WHERE user_id = $1", userID).
		Scan(&data.ID, &ibanEnc, &cfEnc)
	if err != nil {
		return nil, err
	}
	iban, err := pkg.Decrypt(ibanEnc, []byte(os.Getenv("ENCRYPTION_KEY_SENSITIVE_DATA")))
	if err != nil {
		return nil, err
	}
	fc, err := pkg.Decrypt(cfEnc, []byte(os.Getenv("ENCRYPTION_KEY_SENSITIVE_DATA")))
	if err != nil {
		return nil, err
	}
	data.UserID = userID
	ibanStr := string(iban)
	fcStr := string(fc)
	data.IBAN = &ibanStr
	data.FiscalCode = &fcStr
	return &data, nil
}
