package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/initializers"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/models"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/utils"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func SignUpLocal(c *gin.Context) {
	var signUpDto models.SignUpDto
	if err := c.ShouldBindJSON(&signUpDto); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"error":  err.Error(),
		})
		return
	}

	errors := models.ValidateStruct(signUpDto)
	if errors != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"error":  errors,
		})
		return
	}

	if signUpDto.Password != signUpDto.PasswordConfirm {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"error":  "Passwords do not match.",
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signUpDto.Password), bcrypt.DefaultCost)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
			"status": http.StatusBadGateway,
			"error":  err.Error(),
		})
		return
	}

	newUser := models.User{
		Name:     signUpDto.Name,
		Email:    strings.ToLower(signUpDto.Email),
		Password: string(hashedPassword),
	}

	result := initializers.DB.Create(&newUser)
	if result.Error != nil && strings.Contains(result.Error.Error(), "duplicated") {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"status": http.StatusConflict,
			"error":  "User with that email already exists",
		})
		return
	} else if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
			"status": http.StatusBadGateway,
			"error":  "Something bad happened",
		})
		return
	}

	c.AbortWithStatusJSON(http.StatusOK, gin.H{
		"status": http.StatusOK,
		"data": gin.H{
			"user": models.FilterUserRecord(&newUser),
		},
	})
}

func SignInLocal(c *gin.Context) {
	var signInDto models.SignInDto
	if err := c.ShouldBindJSON(&signInDto); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"error":  err.Error(),
		})
		return
	}

	errors := models.ValidateStruct(signInDto)
	if errors != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"error":  errors,
		})
		return
	}

	var user models.User
	err := initializers.DB.First(&user, "email = ?", strings.ToLower(signInDto.Email)).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"status": http.StatusForbidden,
				"error":  "Invalid email or password",
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

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(signInDto.Password))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
			"status": http.StatusBadGateway,
			"error":  err.Error(),
		})
		return
	}

	config, _ := initializers.LoadConfig(".")

	acccessTokenDetails, err := utils.CreateToken(user.ID.String(), config.AccessTokenExpiresIn, config.AccessTokenPrivateKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  err.Error(),
		})
		return
	}

	refreshTokenDetails, err := utils.CreateToken(user.ID.String(), config.RefreshTokenExpiresIn, config.RefreshTokenPrivateKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  err.Error(),
		})
		return
	}

	ctx := context.TODO()
	now := time.Now().Local()

	errAccess := initializers.RedisClient.Set(ctx, acccessTokenDetails.TokenUuid, user.ID.String(), time.Unix(*acccessTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errAccess.Error(),
		})
		return
	}

	errRefresh := initializers.RedisClient.Set(ctx, refreshTokenDetails.TokenUuid, user.ID.String(), time.Unix(*refreshTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errRefresh != nil {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errRefresh.Error(),
		})
		return
	}

	c.SetCookie("access_token", *acccessTokenDetails.Token, config.AccessTokenMaxAge*60, "/", "localhost", false, true)
	c.SetCookie("refresh_token", *refreshTokenDetails.Token, config.RefreshTokenMaxAge*60, "/", "localhost", false, true)
	c.SetCookie("logged_in", "true", config.AccessTokenMaxAge*60, "/", "localhost", false, true)

	c.AbortWithStatusJSON(http.StatusOK, gin.H{
		"status":       http.StatusOK,
		"access_token": acccessTokenDetails.Token,
	})
}

func RefreshAccsessToken(c *gin.Context) {
	refresh_token, err := c.Cookie("refresh_token")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"status": http.StatusForbidden,
			"error":  err.Error(),
		})
		return
	}

	config, _ := initializers.LoadConfig("*")
	ctx := context.TODO()

	tokenClaims, err := utils.ValidateToken(refresh_token, config.RefreshTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"status": http.StatusForbidden,
			"error":  err.Error(),
		})
		return
	}

	userId, err := initializers.RedisClient.Get(ctx, tokenClaims.TokenUuid).Result()
	if err == redis.Nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"status": http.StatusForbidden,
			"error":  err.Error(),
		})
		return
	}

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

	acccessTokenDetails, err := utils.CreateToken(user.ID.String(), config.AccessTokenExpiresIn, config.AccessTokenPrivateKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  err.Error(),
		})
		return
	}

	now := time.Now().Local()

	errAccess := initializers.RedisClient.Set(ctx, acccessTokenDetails.TokenUuid, user.ID.String(), time.Unix(*acccessTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errAccess.Error(),
		})
		return
	}

	c.SetCookie("access_token", *acccessTokenDetails.Token, config.AccessTokenMaxAge*60, "/", "localhost", false, true)
	c.SetCookie("logged_in", "true", config.AccessTokenMaxAge*60, "/", "localhost", false, true)

	c.AbortWithStatusJSON(http.StatusOK, gin.H{
		"status":       http.StatusOK,
		"access_token": acccessTokenDetails.Token,
	})
}

func SignOutLocal(c *gin.Context) {
	refresh_token, err := c.Cookie("refresh_token")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"status": http.StatusForbidden,
			"error":  err.Error(),
		})
		return
	}

	config, _ := initializers.LoadConfig("*")
	ctx := context.TODO()

	tokenClaims, err := utils.ValidateToken(refresh_token, config.RefreshTokenPublicKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"status": http.StatusForbidden,
			"error":  err.Error(),
		})
		return
	}

	access_token_uuid, _ := c.MustGet("access_token_uuid").(string)
	_, err = initializers.RedisClient.Del(ctx, tokenClaims.TokenUuid, access_token_uuid).Result()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
			"status": http.StatusBadGateway,
			"error":  err.Error(),
		})
		return
	}

	c.SetCookie("access_token", "", -1, "/", "localhost", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "localhost", false, true)
	c.SetCookie("logged_in", "", -1, "/", "localhost", false, true)

	c.AbortWithStatusJSON(http.StatusOK, gin.H{
		"status": http.StatusOK,
	})
}
