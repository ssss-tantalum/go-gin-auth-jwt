package main

import (
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/initializers"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/routes"
)

func init() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatalln("Failed to load environment variables! \n", err.Error())
	}
	initializers.ConnectDB(&config)
	initializers.ConnectRedis(&config)
}

func main() {
	app := gin.Default()

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:3000"}
	app.Use(cors.New(corsConfig))

	routes.SetUpRoutes(app)
	app.Run()
}
