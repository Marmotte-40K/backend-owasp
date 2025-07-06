package routes

import (
	"github.com/Marmotte-40K/backend-owasp/handlers"
	"github.com/gin-gonic/gin"
)

func AddAuthRoutes(rg *gin.RouterGroup, h *handlers.AuthHandler) {
	auth := rg.Group("/auth")

	auth.POST("/register", h.Register)

	auth.POST("/login", h.Login)

	auth.POST("/refresh", h.RefreshToken)
}
