package repository

import (
	"context"
	"fmt"
	"log"
	"os"
	"crypto/rand"
    "encoding/base64"
	"auth-service/internal/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

var db *pgxpool.Pool

func InitDB() {
	var err error
	databaseURL := os.Getenv("DATABASE_URL")

	db, err = pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	fmt.Println("Connected to the database")
}

func Migrate() {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		refresh_token VARCHAR(255),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := db.Exec(context.Background(), createTableSQL)
	if err != nil {
		log.Fatalf("Ошибка при создании таблицы: %v\n", err)
	}

	log.Println("Таблица users успешно создана или уже существует")
}

func CreateUser(user *models.User) error {
	_, err := db.Exec(context.Background(), `
		INSERT INTO users (id, email, password_hash, created_at)
		VALUES ($1, $2, $3, $4)`, user.ID, user.Email, user.PasswordHash, user.CreatedAt)
	if err != nil {
		return fmt.Errorf("error creating user: %w", err)
	}
	return nil
}

func GenerateRandomToken() (string, error) {
    tokenLength := 32
    tokenBytes := make([]byte, tokenLength)
    _, err := rand.Read(tokenBytes)
    if err != nil {
        return "", fmt.Errorf("error generating random bytes: %w", err)
    }
    token := base64.URLEncoding.EncodeToString(tokenBytes)

    return token, nil
}

func GetUserEmailByID(userID string) (string, error) {
	var email string
	err := db.QueryRow(context.Background(), "SELECT email FROM users WHERE id=$1", userID).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("error fetching user email: %w", err)
	}
	return email, nil
}

func SaveRefreshTokenHash(userID string, hashedToken string) error {
    _, err := db.Exec(context.Background(), "UPDATE users SET refresh_token=$1 WHERE id=$2", hashedToken, userID)
    if err != nil {
        return fmt.Errorf("error saving refresh token hash: %w", err)
    }
    return nil
}

func GetRefreshTokenHash(userID string) (string, error) {
	var hashedToken string
	err := db.QueryRow(context.Background(), "SELECT refresh_token FROM users WHERE id=$1", userID).Scan(&hashedToken)
	if err != nil {
		return "", fmt.Errorf("error fetching refresh token hash: %w", err)
	}
	return hashedToken, nil
}
