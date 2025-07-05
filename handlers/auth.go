package handlers

import (
	"github.com/Marmotte-40K/backend-owasp/models"
	"github.com/Marmotte-40K/backend-owasp/pkg"
	"github.com/Marmotte-40K/backend-owasp/services"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

type AuthHandler struct {
	svc *services.UserService
}

func NewAuthHandler(svc *services.UserService) *AuthHandler {
	return &AuthHandler{
		svc: svc,
	}
}

type loginBody struct {
	Email    string `json:"email"  binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var body loginBody

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid"})
		return
	}

	user, err := h.svc.GetUserByEmail(c, body.Email)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := pkg.CreateToken(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{
		"message": "Login successful",
		"token":   token,
	})
}

type registerBody struct {
	Name     string `json:"name" binding:"required"`
	Surname  string `json:"surname" binding:"required"`
	Email    string `json:"email"  binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var body registerBody

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	user, err := h.svc.CreateUser(c, &models.User{Name: body.Name, Surname: body.Surname, Email: body.Email, Password: string(hashed)})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	token, err := pkg.CreateToken(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{
		"message": "Registration successful",
		"token":   token,
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Token refreshed successfully",
	})
}
