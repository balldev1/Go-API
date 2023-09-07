package main

import (
	"fmt"
	AuthController "test/jwt-api/controller/auth"
	UserController "test/jwt-api/controller/user"
	"test/jwt-api/middleware"
	_ "test/jwt-api/middleware"
	"test/jwt-api/orm"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

// go orm , go gin core , go bcrypt , go jwt

// from json
type Register struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Fullname string `json:"fullname" binding:"required"`
	Avatar   string `json:"avatar" binding:"required"`
}

// go orm
type User struct {
	gorm.Model
	Username string
	Password string
	Fullname string
	Avatar   string
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	orm.InitDB()

	r := gin.Default()
	r.Use(cors.Default())
	r.POST("/register", AuthController.Register)
	r.POST("/login", AuthController.Login)
	authorized := r.Group("/users", middleware.JWTAuth()) //เช็ค token
	authorized.GET("/readall", UserController.ReadAll)    // ถ้ามี token ให้เรียกใช้readall
	authorized.GET("/profile", UserController.Profile)    // ถ้ามี token ให้เรียกใช้readall
	r.Run("localhost:3333")                               // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
