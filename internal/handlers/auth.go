package handlers

import (
	"auth-service/internal/services"
	"github.com/gin-gonic/gin"
	"net/http"
)

func GenerateTokens(c *gin.Context) {
	userID := c.Query("user_id")
	clientIP := c.ClientIP()

	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	accessToken, refreshToken, err := services.GenerateJWT(userID, clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

type TokenRequest struct {
    RefreshToken string `json:"refresh_token"`
    AccessToken  string `json:"access_token"`
}

func RefreshToken(c *gin.Context) {
    var tokenReq TokenRequest
    if err := c.ShouldBindJSON(&tokenReq); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }
    refreshToken := tokenReq.RefreshToken
    accessToken := tokenReq.AccessToken
    clientIP := c.ClientIP()

    if refreshToken == "" || accessToken == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Tokens are required"})
        return
    }

    newAccessToken, newRefreshToken, err := services.RefreshTokens(accessToken, refreshToken, clientIP)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "new_access_token":  newAccessToken,
        "new_refresh_token": newRefreshToken,
    })
}
