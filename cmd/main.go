package main

import (
	"auth-service/internal/config"
	"auth-service/internal/handlers"
	"auth-service/internal/repository"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()
	repository.InitDB()
	repository.Migrate()
	r := gin.Default()
	r.POST("/register", handlers.RegisterHandler)
	r.POST("/login", handlers.GenerateTokens)
	r.POST("/refresh", handlers.RefreshToken)
	r.Run(":8080")
}
