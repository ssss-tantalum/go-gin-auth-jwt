package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/initializers"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/models"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/utils"
	"gorm.io/gorm"
)

func DeserializeUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var access_token string
		authorization := c.Request.Header.Get("Authorization")
		access_token, _ = c.Cookie("access_token")

		if strings.HasPrefix(authorization, "Bearer ") {
			access_token = strings.TrimPrefix(authorization, "Bearer ")
		}
		if access_token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"status": http.StatusUnauthorized,
				"error":  "You are not logged in",
			})
			return
		}

		config, _ := initializers.LoadConfig(".")

		tokenClaims, err := utils.ValidateToken(access_token, config.AccessTokenPublicKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"status": http.StatusForbidden,
				"error":  err.Error(),
			})
			return
		}

		ctx := context.TODO()
		userId, err := initializers.RedisClient.Get(ctx, tokenClaims.TokenUuid).Result()
		if err == redis.Nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"status": http.StatusForbidden,
				"error":  err.Error(),
			})
			return
		}

		fmt.Printf("userId: %v", userId)

		var user models.User
		err = initializers.DB.First(&user, "id = ?", userId).Error
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"status": http.StatusForbidden,
					"error":  err.Error(),
				})
				return
			} else {
				c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
					"status": http.StatusBadGateway,
					"error":  err.Error(),
				})
				return
			}
		}

		c.Set("user", models.FilterUserRecord(&user))

		fmt.Printf("user: %v", c.MustGet("user"))

		c.Set("access_token_uuid", tokenClaims.TokenUuid)
	}
}
