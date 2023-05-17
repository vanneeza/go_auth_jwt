package main

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/vanneeza/go_auth_jwt/auth"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var jwtKey = []byte("SECRET_KEY_BEBAS")

func main() {

	r := gin.Default()
	r.POST("/auth/login", loginHandler)
	userRouter := r.Group("api/v1/users")
	userRouter.Use(auth.AuthMiddleware())
	userRouter.GET("/:id/profile", profileHandler)
	r.Run(":8080")
}

func loginHandler(c *gin.Context) {
	var user User

	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if user.Username == "enigma" && user.Password == "12345" {

		token := jwt.New(jwt.SigningMethodHS256)

		claims := token.Claims.(jwt.MapClaims)

		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(time.Minute * 1).Unix()

		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func profileHandler(c *gin.Context) {

	claims := c.MustGet("claims").(jwt.MapClaims)
	username := claims["username"].(string)

	c.JSON(http.StatusOK, gin.H{"username": username})
}
