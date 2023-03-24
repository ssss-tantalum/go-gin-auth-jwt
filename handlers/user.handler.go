package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ssss-tantalum/go-gin-jwt-rs-256/models"
)

func ShowProfile(c *gin.Context) {
	user := c.MustGet("user").(models.UserResponse)

	c.AbortWithStatusJSON(http.StatusOK, gin.H{
		"status": http.StatusOK,
		"data":   user,
	})
}
