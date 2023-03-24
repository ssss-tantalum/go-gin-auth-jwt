package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/handlers"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/middlewares"
)

func SetUpRoutes(app *gin.Engine) {
	v1 := app.Group("/api/v1")

	auth := v1.Group("/auth")
	{
		auth.POST("/signup", handlers.SignUpLocal)
		auth.POST("/signin", handlers.SignInLocal)
		auth.GET("/signout", middlewares.DeserializeUser(), handlers.SignOutLocal)
		auth.GET("/refresh", handlers.RefreshAccsessToken)
	}

	user := v1.Group("/users")
	{
		user.GET("/:id", middlewares.DeserializeUser(), handlers.ShowProfile)
	}
}
