package pkg

import (
	"encoding/json"
	"log"
	"strings"
)

var SensitiveKeys = []string{"password", "token", "iban", "fiscal_code", "totp_code", "manual_entry_key", "secret", "new_password", "old_password"}

func MaskSensitiveData(data map[string]interface{}) map[string]interface{} {
	masked := make(map[string]interface{})
	for k, v := range data {
		lowerK := strings.ToLower(k)
		maskedValue := v
		for _, sensitive := range SensitiveKeys {
			if lowerK == sensitive {
				maskedValue = "***"
				break
			}
		}
		masked[k] = maskedValue
	}
	return masked
}

func LogError(context string, err error, details map[string]interface{}) {
	masked := MaskSensitiveData(details)
	detailsJSON, _ := json.Marshal(masked)
	log.SetOutput(GetLogWriter("error"))
	log.Printf("[ERROR] %s: %v | details: %s", context, err, detailsJSON)
}

func LogFailedLogin(details map[string]interface{}) {
	masked := MaskSensitiveData(details)
	detailsJSON, _ := json.Marshal(masked)
	log.SetOutput(GetLogWriter("failed-login"))
	log.Printf("[FAILED LOGIN] details: %s", detailsJSON)
}
