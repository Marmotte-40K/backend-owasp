package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func AddAuthRoutes(rg *gin.RouterGroup) {
	auth := rg.Group("/auth")

	auth.POST("/register", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "User registered successfully",
		})
	})

	auth.POST("/login", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Login successful",
		})
	})
}
