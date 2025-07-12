package handlers

import (
	"net/http"
	"strconv"

	"github.com/Marmotte-40K/backend-owasp/models"
	"github.com/Marmotte-40K/backend-owasp/services"
	"github.com/gin-gonic/gin"
)

type TOTPHandler struct {
	totpService *services.TOTPService
	userService *services.UserService
}

func NewTOTPHandler(totpService *services.TOTPService, userService *services.UserService) *TOTPHandler {
	return &TOTPHandler{
		totpService: totpService,
		userService: userService,
	}
}

func (h *TOTPHandler) GetQRCode(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := h.userService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.TotpSecret == "" {
		secret, err := h.userService.GenerateTOTPSecret()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate TOTP secret"})
			return
		}
		err = h.userService.UpdateTOTPSecret(c.Request.Context(), userID, secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save TOTP secret"})
			return
		}
		user.TotpSecret = secret
	}

	response, err := h.totpService.GenerateQRCode(user, "Marmotte-40K/backend-owasp")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *TOTPHandler) EnableTOTP(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req models.TOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify TOTP code
	if !h.totpService.ValidateCode(req.TOTPCode, user.TotpSecret) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid TOTP code"})
		return
	}

	// Enable TOTP
	err = h.userService.UpdateTOTPEnabled(c.Request.Context(), userID, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable TOTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "TOTP enabled successfully"})
}

func (h *TOTPHandler) DisableTOTP(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req models.TOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !h.totpService.ValidateCode(req.TOTPCode, user.TotpSecret) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid TOTP code"})
		return
	}

	err = h.userService.UpdateTOTPEnabled(c.Request.Context(), userID, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable TOTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "TOTP disabled successfully"})
}

func (h *TOTPHandler) VerifyTOTP(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req models.TOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	valid := h.totpService.ValidateCode(req.TOTPCode, user.TotpSecret)

	c.JSON(http.StatusOK, gin.H{
		"valid": valid,
		"message": func() string {
			if valid {
				return "TOTP code is valid"
			}
			return "TOTP code is invalid"
		}(),
	})
}
