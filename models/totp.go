package models

type TOTPResponse struct {
	QRCode         string `json:"qr_code"`
	Secret         string `json:"secret"`
	ManualEntryKey string `json:"manual_entry_key"`
}

type TOTPRequest struct {
	TOTPCode string `json:"totp_code" binding:"required"`
}
