package services

import (
	"auth-service/internal/repository"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"os"
	"time"
    "golang.org/x/crypto/bcrypt"
)

type Claims struct {
	UserID  string `json:"user_id"`
	ClientIP string `json:"client_ip"`
	jwt.RegisteredClaims
}

func GenerateJWT(userID, clientIP string) (string, string, error) {
    claims := Claims{
        UserID:   userID,
        ClientIP: clientIP,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
    accessToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
    if err != nil {
        return "", "", fmt.Errorf("could not create access token: %v", err)
    }
    refreshToken, err := repository.GenerateRandomToken()
    if err != nil {
        return "", "", fmt.Errorf("could not generate refresh token: %v", err)
    }
    hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
    if err != nil {
        return "", "", fmt.Errorf("could not hash refresh token: %v", err)
    }
    err = repository.SaveRefreshTokenHash(userID, string(hashedToken))
    if err != nil {
        return "", "", fmt.Errorf("could not save refresh token hash: %v", err)
    }
    return accessToken, refreshToken, nil
}

func RefreshTokens(accessTokenStr, refreshToken, clientIP string) (string, string, error) {
    token, err := jwt.ParseWithClaims(accessTokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte(os.Getenv("JWT_SECRET")), nil
    })
    if err != nil {
        return "", "", fmt.Errorf("invalid access token: %v", err)
    }

    claims, ok := token.Claims.(*Claims)
    if !ok || !token.Valid {
        return "", "", fmt.Errorf("invalid access token claims")
    }
    if claims.ClientIP != clientIP {
        email, err := repository.GetUserEmailByID(claims.UserID)
        if err != nil {
            return "", "", fmt.Errorf("could not get user email: %v", err)
        }
        fmt.Printf("Warning: IP address changed for user %s. Sending email to %s\n", claims.UserID, email)
    }
    hashedToken, err := repository.GetRefreshTokenHash(claims.UserID)
    if err != nil {
        return "", "", fmt.Errorf("could not get refresh token hash: %v", err)
    }
    err = bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken))
    if err != nil {
        return "", "", fmt.Errorf("invalid refresh token")
    }
    return GenerateJWT(claims.UserID, clientIP)
}
