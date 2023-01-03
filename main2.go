package main

import (
    "fmt"
    "log"
    "time"

    "github.com/gofiber/fiber"
    "github.com/jinzhu/gorm"
    _ "github.com/jinzhu/gorm/dialects/postgres"
    "github.com/dgrijalva/jwt-go"
)

// Configure our Postgres connection strings
const (
    host     = "localhost"
    port     = 5432
    user     = "postgres"
    password = "password"
    dbname   = "fiber_db"
)

// Create our database connection
var db *gorm.DB

// Create our JWT signing key
var jwtKey = []byte("secret")

// Create our JWT claims
type Claims struct {
    UserID uint
    jwt.StandardClaims
}

func main() {
    // Connect to our Postgres database
    psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
        "password=%s dbname=%s sslmode=disable",
        host, port, user, password, dbname)
    var err error
    db, err = gorm.Open("postgres", psqlInfo)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Automigrate our models
    db.AutoMigrate(&User{}, &Post{}, &Comment{})

    // Create our Fiber instance
    app := fiber.New()

    // Create our authentication endpoints
    app.Post("/signup", signup)
    app.Post("/login", login)

    // Create our authorization middleware
    app.Use(authorize)

    // Create our resource endpoints
    app.Get("/users", getUsers)
    app.Get("/users/:id", getUser)
    app.Post("/users", createUser)
    app.Put("/users/:id", updateUser)
    app.Delete("/users/:id", deleteUser)

    app.Get("/posts", getPosts)
    app.Get("/posts/:id", getPost)
    app.Post("/posts", createPost)
    app.Put("/posts/:id", updatePost)
    app.Delete("/posts/:id", deletePost)

    app.Get("/comments", getComments)
    app.Get("/comments/:id", getComment)
    app.Post("/comments", createComment)
    app.Put("/comments/:id", updateComment)
    app.Delete("/comments/:id", deleteComment)

    // Start our server
    log.Fatal(app.Listen(":3000"))
}

// User model
type User struct {
    gorm.Model
    Name     string `json:"name"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

// Post model
type Post struct {
    gorm.Model
    UserID uint   `json:"user_id"`
    Title  string `json:"title"`
    Body   string `json:"body"`
}

// Comment model
type Comment struct {
    gorm.Model
    PostID  uint   `json:"post_id"`
    UserID  uint   `json:"user_id"`
    Comment string `json:"comment"`
}

// Signup endpoint
func signup(c *fiber.Ctx) {
    // Get user data
    user := new(User)
    if err := c.BodyParser(user); err != nil {
        c.Status(500).Send(err)
        return
    }

    // Create user
    if err := db.Create(&user).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Create JWT
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        UserID: user.ID,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(fiber.Map{
        "token": tokenString,
        "user":  user,
    })
}

// Login endpoint
func login(c *fiber.Ctx) {
    // Get user data
    user := new(User)
    if err := c.BodyParser(user); err != nil {
        c.Status(500).Send(err)
        return
    }

    // Get user from database
    if err := db.Where("email = ?", user.Email).First(&user).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Compare passwords
    if !comparePasswords(user.Password, []byte(user.Password)) {
        c.Status(403).Send("incorrect password")
        return
    }

    // Create JWT
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        UserID: user.ID,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(fiber.Map{
        "token": tokenString,
        "user":  user,
    })
}

// Authorization middleware
func authorize(c *fiber.Ctx) {
    // Get token from request
    tokenString := c.Get("Authorization")
    if tokenString == "" {
        c.Status(403).Send("missing token")
        return
    }

    // Parse token
    claims := &Claims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil {
        if err == jwt.ErrSignatureInvalid {
            c.Status(403).Send("invalid token")
            return
        }
        c.Status(500).Send(err)
        return
    }
    if !token.Valid {
        c.Status(403).Send("invalid token")
        return
    }

    // Get user from database
    user := &User{}
    if err := db.First(&user, claims.UserID).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Set user to context
    c.Locals("user", user)

    // Pass control to the next handler
    c.Next()
}

// Get users endpoint
func getUsers(c *fiber.Ctx) {
    // Get all users
    users := []User{}
    if err := db.Find(&users).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(users)
}

// Get user endpoint
func getUser(c *fiber.Ctx) {
    // Get user from database
    user := new(User)
    if err := db.First(&user, c.Params("id")).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Send response
    c.JSON(user)
}

// Create user endpoint
func createUser(c *fiber.Ctx) {
    // Get user data
    user := new(User)
    if err := c.BodyParser(user); err != nil {
        c.Status(500).Send(err)
       

    }

    // Create user
    if err := db.Create(&user).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(user)
}

// Update user endpoint
func updateUser(c *fiber.Ctx) {
    // Get user from database
    user := new(User)
    if err := db.First(&user, c.Params("id")).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Update user
    if err := c.BodyParser(user); err != nil {
        c.Status(500).Send(err)
        return
    }
    if err := db.Save(&user).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(user)
}

// Delete user endpoint
func deleteUser(c *fiber.Ctx) {
    // Get user from database
    user := new(User)
    if err := db.First(&user, c.Params("id")).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Delete user
    if err := db.Delete(&user).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.Send("user deleted")
}

// Get posts endpoint
func getPosts(c *fiber.Ctx) {
    // Get all posts
    posts := []Post{}
    if err := db.Find(&posts).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(posts)
}

// Get post endpoint
func getPost(c *fiber.Ctx) {
    // Get post from database
    post := new(Post)
    if err := db.First(&post, c.Params("id")).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Send response
    c.JSON(post)
}

// Create post endpoint
func createPost(c *fiber.Ctx) {
    // Get post data
    post := new(Post)
    if err := c.BodyParser(post); err != nil {
        c.Status(500).Send(err)
        return
    }

    // Create post
    if err := db.Create(&post).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(post)
}

// Update post endpoint
func updatePost(c *fiber.Ctx) {
    // Get post from database
    post := new(Post)
    if err := db.First(&post, c.Params("id")).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Update post
    if err := c.BodyParser(post); err != nil {
        c.Status(500).Send(err)
        return
    }
    if err := db.Save(&post).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(post)
}

// Delete post endpoint
func deletePost(c *fiber.Ctx) {
    // Get post from database
    post := new(Post)
    if err := db.First(&post, c.Params("id")).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Delete post
    if err := db.Delete(&post).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.Send("post deleted")
}

// Get comments endpoint
func getComments(c *fiber.Ctx) {
    // Get all comments
    comments := []Comment{}
    if err := db.Find(&comments).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(comments)
}

// Get comment endpoint
func getComment(c *fiber.Ctx) {
    // Get comment from database
    comment := new(Comment)
    if err := db.First(&comment, c.Params("id")).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Send response
    c.JSON(comment)
}

// Create comment endpoint
func createComment(c *fiber.Ctx) {
    // Get comment data
    comment := new(Comment)
    if err := c.BodyParser(comment); err != nil {
        c.Status(500).Send(err)
        return
    }

    // Create comment
    if err := db.Create(&comment).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(comment)
}

// Update comment endpoint
func updateComment(c *fiber.Ctx) {
    // Get comment from database
    comment := new(Comment)
    if err := db.First(&comment, c.Params("id")).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Update comment
    if err := c.BodyParser(comment);


        err != nil {
        c.Status(500).Send(err)
        return
    }
    if err := db.Save(&comment).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.JSON(comment)
}

// Delete comment endpoint
func deleteComment(c *fiber.Ctx) {
    // Get comment from database
    comment := new(Comment)
    if err := db.First(&comment, c.Params("id")).Error; err != nil {
        c.Status(404).Send(err)
        return
    }

    // Delete comment
    if err := db.Delete(&comment).Error; err != nil {
        c.Status(500).Send(err)
        return
    }

    // Send response
    c.Send("comment deleted")
}

// Compare passwords
func comparePasswords(hashedPwd string, plainPwd []byte) bool {
    // Since we'll be getting the hashed password from the DB it
    // will be a string so we'll need to convert it to a byte slice
    byteHash := []byte(hashedPwd)
    err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
    if err != nil {
        log.Println(err)
        return false
    }

    return true
}