package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber"
	_ "github.com/lib/pq"
	"github.com/dgrijalva/jwt-go"
)

// Database Connection
const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "password"
	dbname   = "backend"
)

func main() {
	// Establish database connection
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Create Fiber App
	app := fiber.New()

	// JWT Middleware
	jwtMiddleware := func(c *fiber.Ctx) {
		// Get token from Authorization header
		authHeader := c.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		tokenString := bearerToken[1]

		// Validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return []byte("my_secret_key"), nil
		})

		if err != nil {
			c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Failed to authenticate token",
			})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			fmt.Println(claims["user_id"], claims["username"])
			// Check if token is still valid
			if time.Unix(int64(claims["exp"].(float64)), 0).Before(time.Now()) {
				c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Token has expired",
				})
				return
			}
			c.Next()
			return
		} else {
			c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token",
			})
			return
		}
	}

	// GET Endpoint
	app.Get("/users", jwtMiddleware, func(c *fiber.Ctx) {
		rows, err := db.Query("SELECT id, username FROM users")
		if err != nil {
			c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
			return
		}
		defer rows.Close()

		var users []fiber.Map
		for rows.Next() {
			var id int
			var username string
			if err := rows.Scan(&id, &username); err != nil {
				c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": err.Error(),
				})
				return
			}
			users = append(users, fiber.Map{
				"id":       id,
				"username": username,
			})
		}

		c.JSON(fiber.Map{
			"users": users,
		})
	})

	// POST Endpoint
	app.Post("/users", jwtMiddleware, func(c *fiber.Ctx) {
		username := c.FormValue("username")

		_, err := db.Exec("INSERT INTO users (username) VALUES ($1)", username)
		if err != nil {
			c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
			return
		}

		c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": "User successfully created",
		})
	})

	// PUT Endpoint
	app.Put("/users/:id", jwtMiddleware, func(c *fiber.Ctx) {
		id := c.Params("id")
		username := c.FormValue("username")

		_, err := db.Exec("UPDATE users SET username = $1 WHERE id = $2", username, id)
		if err != nil {
			c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
			return
		}

		c.Status(fiber.StatusAccepted).JSON(fiber.Map{
			"message": "User successfully updated",
		})
	})

	// DELETE Endpoint
	app.Delete("/users/:id", jwtMiddleware, func(c *fiber.Ctx) {
		id := c.Params("id")

		_, err := db.Exec("DELETE FROM users where id = $1", id)
		if err != nil {
			c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
			return
		}

		c.Status(fiber.StatusNoContent).JSON(fiber.Map{
			"message": "User successfully deleted",
		})
	})

	// Start server
	log.Fatal(app.Listen(":3000"))
}