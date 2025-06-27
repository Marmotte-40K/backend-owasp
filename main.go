package main

import (
	"net/http"

	"github.com/Marmotte-40K/backend-owasp/routes"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Service online",
		})
	})

	v1 := router.Group("/v1")
	routes.AddAuthRoutes(v1)

	router.Run()
}
