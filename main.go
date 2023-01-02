package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber"
	"github.com/dgrijalva/jwt-go"
)

// JWTSecret is used to create and verify our tokens
var JWTSecret = []byte("supersecretkey")

// User is a basic user type
type User struct {
	Username string
	Password string
}

// Users is a map of users
var Users = map[string]User{
	"admin": {
		Username: "admin",
		Password: "password",
	},
}

func main() {
	app := fiber.New()

	app.Use("/", authenticationMiddleware)
	app.Use("/admin", authorizationMiddleware)

	app.Get("/", func(c *fiber.Ctx) {
		c.Send("Hello World")
	})

	app.Get("/admin", func(c *fiber.Ctx) {
		c.Send("Welcome to the admin page")
	})

	app.Listen(":3000")
}

// authenticationMiddleware is used to authenticate a user
func authenticationMiddleware(c *fiber.Ctx) {
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Check if the username and password are valid
	user, ok := Users[username]
	if !ok || user.Password != password {
		c.Status(http.StatusUnauthorized).Send("Unauthorized")
		return
	}

	// Create a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set some claims
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	// Generate encoded token and send it as response.
	t, err := token.SignedString(JWTSecret)
	if err != nil {
		c.Status(http.StatusInternalServerError).Send(err.Error())
		return
	}

	c.Send(fmt.Sprintf("token: %s", t))
}

// authorizationMiddleware is used to authorize a user
func authorizationMiddleware(c *fiber.Ctx) {
	// Get token from request
	tokenStr := c.FormValue("token")
	if tokenStr == "" {
		c.Status(http.StatusUnauthorized).Send("Unauthorized")
		return
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return JWTSecret, nil
	})
	if err != nil {
		c.Status(http.StatusUnauthorized).Send("Unauthorized")
		return
	}

	if !token.Valid {
		c.Status(http.StatusUnauthorized).Send("Unauthorized")
		return
	}

	c.Next()
}