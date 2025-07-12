package handlers

import (
	"net/http"
	"strconv"

	"github.com/Marmotte-40K/backend-owasp/models"
	"github.com/Marmotte-40K/backend-owasp/services"
	"github.com/gin-gonic/gin"
)

type SensitiveDataHandler struct {
	svc *services.SensitiveDataService
}

func NewSensitiveDataHandler(svc *services.SensitiveDataService) *SensitiveDataHandler {
	return &SensitiveDataHandler{svc: svc}
}

type bodyRequest struct {
	IBAN       *string `json:"iban,omitempty"`
	FiscalCode *string `json:"fiscal_code,omitempty"`
}

func (h *SensitiveDataHandler) SaveOrUpdate(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}
	var body bodyRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.IBAN == nil && body.FiscalCode == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one field (iban or fiscal_code) required"})
		return
	}
	if err := h.svc.SaveOrUpdate(c.Request.Context(), &models.SensitiveData{UserID: userID, IBAN: body.IBAN, FiscalCode: body.FiscalCode}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save sensitive data"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Sensitive data saved"})
}

func (h *SensitiveDataHandler) Get(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}
	data, err := h.svc.GetByUserID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Sensitive data not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"iban":        data.IBAN,
		"fiscal_code": data.FiscalCode,
	})
}
