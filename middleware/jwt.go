package middleware

import (
	"net/http"

	"github.com/Marmotte-40K/backend-owasp/pkg"
	"github.com/gin-gonic/gin"
)

// ...existing code...

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("access_token")
		if err != nil || tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid token"})
			return
		}
		if err := pkg.ValidateToken(tokenString); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}
		c.Next()
	}
}
