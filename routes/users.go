package routes

import (
	"github.com/Marmotte-40K/backend-owasp/handlers"
	"github.com/gin-gonic/gin"
)

func AddUserRoutes(rg *gin.RouterGroup, h *handlers.TOTPHandler) {
	users := rg.Group("/users")

	users.GET("/:user_id/totp/qr", h.GetQRCode)
	users.POST("/:user_id/totp/enable", h.EnableTOTP)
	users.POST("/:user_id/totp/disable", h.DisableTOTP)
	users.POST("/:user_id/totp/verify", h.VerifyTOTP)
}
