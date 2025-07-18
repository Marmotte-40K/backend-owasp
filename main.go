package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Marmotte-40K/backend-owasp/handlers"
	"github.com/Marmotte-40K/backend-owasp/middleware"
	"github.com/Marmotte-40K/backend-owasp/routes"
	"github.com/Marmotte-40K/backend-owasp/services"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

func init() {
	var err error
	pool, err = pgxpool.New(context.Background(), fmt.Sprintf("postgres://%s:%s@%s:%s/%s", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_DATABASE")))

	if err != nil {
		log.Fatal("Unable to create connection pool:", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		log.Fatal("Unable to ping database:", err)
	}

	fmt.Println("Connected to PostgreSQL database!")
}

func main() {

	router := gin.Default()

	defer pool.Close()

	userService := services.NewUserService(pool)
	tokenService := services.NewTokenService(pool)
	totpService := services.NewTOTPService(pool)
	sensitiveDataService := services.NewSensitiveDataService(pool)
	authHandler := handlers.NewAuthHandler(userService, tokenService)
	totpHandler := handlers.NewTOTPHandler(totpService, userService)
	sensitiveDataHandler := handlers.NewSensitiveDataHandler(sensitiveDataService)

	router.Use(middleware.CORSMiddleware())

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Service online",
		})
	})

	v1 := router.Group("/v1")
	v1.Use(middleware.LogRequestResponse())
	routes.AddAuthRoutes(v1, authHandler)
	protected := v1.Group("/")
	protected.Use(middleware.JWTAuthMiddleware())
	protected.GET("/auth/@me", authHandler.Me)
	protected.POST("/auth/change-password", authHandler.ChangePassword)
	protected.POST("/auth/2fa/setup", authHandler.Set2FAMethod)
	routes.AddUserRoutes(protected, totpHandler, sensitiveDataHandler)

	router.Run()
}
