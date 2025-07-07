package handlers

import (
	"net/http"
	"os"
	"time"

	"github.com/Marmotte-40K/backend-owasp/models"
	"github.com/Marmotte-40K/backend-owasp/pkg"
	"github.com/Marmotte-40K/backend-owasp/services"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	svcUser  *services.UserService
	svcToken *services.TokenService
}

func NewAuthHandler(svcUser *services.UserService, svcToken *services.TokenService) *AuthHandler {
	return &AuthHandler{
		svcUser:  svcUser,
		svcToken: svcToken,
	}
}

var domain = os.Getenv("DOMAIN")

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

	user, err := h.svcUser.GetUserByEmail(c.Request.Context(), body.Email)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	dbToken, err := h.svcToken.GetRefreshToken(c.Request.Context(), user.ID)
	if err != nil && err.Error() != "no rows in result set" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if dbToken != "" {
		err = h.svcToken.RemoveRefreshToken(c.Request.Context(), user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
	}

	expToken := time.Now().Add(15 * time.Minute)
	token, err := pkg.CreateToken(user.ID, expToken.Unix())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	expRefresh := time.Now().Add(time.Hour * 24 * 7)

	refreshToken, err := pkg.CreateToken(user.ID, expRefresh.Unix())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	err = h.svcToken.AddRefreshToken(c.Request.Context(), user.ID, refreshToken, expRefresh)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.SetCookie("access_token", token, int(expToken.Second()), "/", domain, false, true)
	c.SetCookie("refresh_token", refreshToken, int(expRefresh.Second()), "/", domain, false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
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

	user, err := h.svcUser.CreateUser(c, &models.User{Name: body.Name, Surname: body.Surname, Email: body.Email, Password: string(hashed)})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	expToken := time.Now().Add(15 * time.Minute)
	token, err := pkg.CreateToken(user.ID, expToken.Unix())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	expRefresh := time.Now().Add(time.Hour * 24 * 7)

	refreshToken, err := pkg.CreateToken(user.ID, expRefresh.Unix())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	err = h.svcToken.AddRefreshToken(c.Request.Context(), user.ID, refreshToken, expRefresh)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.SetCookie("access_token", token, int(expToken.Second()), "/", domain, false, true)
	c.SetCookie("refresh_token", refreshToken, int(expRefresh.Second()), "/", domain, false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	err = pkg.ValidateToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	userID, err := pkg.GetUserIDFromToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	dbToken, err := h.svcToken.GetRefreshToken(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if dbToken != refreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	expToken := time.Now().Add(15 * time.Minute)
	newToken, err := pkg.CreateToken(int(userID), expToken.Unix())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.SetCookie("access_token", newToken, int(expToken.Second()), "/", domain, false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed successfully"})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")

	userID, err := pkg.GetUserIDFromToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	err = h.svcToken.RemoveRefreshToken(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.SetCookie("refresh_token", "", -1, "/", domain, false, true)
	c.SetCookie("access_token", "", -1, "/", domain, false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}
