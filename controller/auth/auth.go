package auth

import (
	"fmt"
	"net/http"
	"os"
	"test/jwt-api/orm"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

// เก็บ key jwt
var hmacSampleSecret []byte

// from register json
type RegisterBody struct {
	Username string `json:'username' binding:'required'`
	Password string `json:'password'  binding:'required'`
	Fullname string `json:'fullname'  binding:'required'`
	Avatar   string `json:'avatar'  binding:'required'`
}

func Register(c *gin.Context) {
	var json RegisterBody
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check User Exists 		//ถ้ามี usernameอยู่แล้วให้ return หยุดการสมัครห้ามซ้ำกัน
	var userExist orm.User
	orm.Db.Where("username = ?", json.Username).First(&userExist)
	if userExist.ID > 0 {
		c.JSON(http.StatusOK, gin.H{"status": "error", "message": "User Exist"})
		return
	}

	//Create user
	encryptedPassword, _ := bcrypt.GenerateFromPassword([]byte(json.Password), 10) //hash password
	user := orm.User{Username: json.Username, Password: string(encryptedPassword),
		Fullname: json.Fullname, Avatar: json.Avatar}
	orm.Db.Create(&user)
	if user.ID > 0 {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "User Create Success", "userId": user.ID})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": "error", "message": "User Create Failed"})
	}
}

// from Login json
type LoginBody struct {
	Username string `json:'username' binding:'required'`
	Password string `json:'password'  binding:'required'`
}

func Login(c *gin.Context) {
	var json LoginBody
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Check User Exists 		//ถ้ามี usernameอยู่แล้วให้ return หยุดการสมัครห้ามซ้ำกัน
	var userExist orm.User
	orm.Db.Where("username = ?", json.Username).First(&userExist)
	// เช็คว่ามี user ไหม
	if userExist.ID == 0 {
		c.JSON(http.StatusOK, gin.H{"status": "error", "message": "User Does Not Exist"})
		return
	}
	//เปรียบเทียบ password db กับ body ถ้ามี ค่า == nil success
	err := bcrypt.CompareHashAndPassword([]byte(userExist.Password), []byte(json.Password))
	if err == nil {
		// JWT
		hmacSampleSecret = []byte(os.Getenv("JWT_SECRET_KEY"))
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"userId": "userExist.ID",
			"exp":    time.Now().Add(time.Minute * 1).Unix(), //เวลา token jwt
		})
		tokenString, err := token.SignedString(hmacSampleSecret)
		fmt.Println(tokenString, err)

		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Login Success", "token": tokenString})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": "error", "message": "Login Failed"})
	}
}
