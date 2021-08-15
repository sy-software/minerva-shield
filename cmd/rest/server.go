package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sy-software/minerva-shield/internal/core/domain"
	"github.com/sy-software/minerva-shield/internal/core/service"
	"github.com/sy-software/minerva-shield/internal/handlers"
	"github.com/sy-software/minerva-shield/internal/repositories"
)

const defaultConfigFile = "./config.json"

func main() {
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = defaultConfigFile
	}

	config := domain.LoadConfiguration(configFile)

	firebaseVal := repositories.NewFirebaseTokenValidator(&config)
	minervaVal := repositories.NewMinervaTokenValidator(&config)
	proxy := repositories.NewProxyCaller(&config)

	proxyService := service.NewProxyService(
		&config,
		proxy,
		firebaseVal,
		minervaVal,
	)

	restHandler := handlers.NewRestHandler(&config, proxyService)

	router := gin.Default()
	router.Any("/*resource", func(c *gin.Context) {
		fmt.Printf("Headers: %+v\n", c.Request.Header)
		fmt.Printf("Resource: %q\n", c.Param("resource"))

		restHandler.CallProxy(c)
		//c.JSON(http.StatusOK, gin.H{"data": "hello world"})
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", config.Host, config.Port),
		Handler: router,
	}

	// Initializing the server in a goroutine so that
	// it won't block the graceful shutdown handling below
	go func() {
		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			log.Printf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be catch, so don't need add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}
