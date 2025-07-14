package routes

import (
	"github.com/Marmotte-40K/backend-owasp/handlers"
	"github.com/gin-gonic/gin"
)

func AddUserRoutes(rg *gin.RouterGroup, hTotp *handlers.TOTPHandler, hSD *handlers.SensitiveDataHandler) {
	users := rg.Group("/users")

	users.GET("/:user_id/totp/qr", hTotp.GetQRCode)
	users.POST("/:user_id/totp/enable", hTotp.EnableTOTP)
	users.POST("/:user_id/totp/disable", hTotp.DisableTOTP)
	users.POST("/:user_id/totp/verify", hTotp.VerifyTOTP)

	users.POST("/:user_id/sensitive", hSD.SaveOrUpdate)
	users.PUT("/:user_id/sensitive", hSD.SaveOrUpdate)
	users.GET("/:user_id/sensitive", hSD.Get)
}
