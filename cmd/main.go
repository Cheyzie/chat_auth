package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Cheyzie/chat_auth/internal/handlers"
	"github.com/Cheyzie/chat_auth/internal/repository"
	"github.com/Cheyzie/chat_auth/internal/service"
	"github.com/Cheyzie/chat_auth/server"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func initEnv() {
	if _, err := os.Stat(".env"); err == nil {
		var fileEnv map[string]string
		fileEnv, err := godotenv.Read()
		if err != nil {
			log.Println("env file unavailable")
		}

		for key, val := range fileEnv {
			if len(os.Getenv(key)) == 0 {
				os.Setenv(key, val)
			}
		}
	}
}

func main() {
	initEnv()
	db, err := repository.NewPostgresDB(repository.SqlConfig{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Username: os.Getenv("DB_USERNAME"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   os.Getenv("DB_DATABASE"),
		SSLMode:  "disable",
	})
	if err != nil {
		log.Fatalf("error occured on db connection: %s", err)
	}
	authRepo := repository.NewUserPostgres(db)
	rtRepo := repository.NewRefreshTokenPostgres(db)
	authService := service.NewAuthorizationService(authRepo, rtRepo)
	handler := handlers.NewHandler(authService)
	router := handler.InitRoutes()

	srv := server.NewServer("8080", router)
	go func() {
		if err := srv.Run(); err != nil {
			log.Fatalf("run server error: %s", err.Error())
		}
	}()
	log.Println("server is started...")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	log.Println("server shutting down...")

	if err := srv.Shutdown(context.Background()); err != nil {
		log.Fatalf("error caused on server shutting down: %s", err)
	}
}
