package pkg

import (
	"github.com/golang-jwt/jwt/v5"
	"os"
)

var secretKey = []byte(os.Getenv("SECRET_KEY"))

func CreateToken(userID int, exp int64) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": userID, "exp": exp})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateToken(tokenString string) error {
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return err
	}

	return nil
}
