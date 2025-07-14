package models

type SensitiveData struct {
	ID         int64
	UserID     int64
	IBAN       *string
	FiscalCode *string
}
