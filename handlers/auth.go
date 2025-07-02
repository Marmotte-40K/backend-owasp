package handlers

import (
	"github.com/Marmotte-40K/backend-owasp/services"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	svc *services.UserService
}

func NewAuthHandler(svc *services.UserService) *AuthHandler {
	return &AuthHandler{
		svc: svc,
	}
}

func (h *AuthHandler) Login(c *gin.Context) {
	// TODO: Change logic, this is just a test
	email := c.Request.FormValue("email")
	if email == "" {
		c.JSON(400, gin.H{
			"error": "Email is required",
		})
		return
	}

	user, err := h.svc.GetUserByEmail(c, email)

	if err != nil {
		c.JSON(404, gin.H{
			"error": "User not found",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "Login successful",
		"user": gin.H{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
		},
	})
}

func (h *AuthHandler) Register(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Registration successful",
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Token refreshed successfully",
	})
}
