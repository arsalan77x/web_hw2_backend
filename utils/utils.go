package utils

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User_account struct {
	User_id       uint   `gorm:"primary_key"`
	Email         string `gorm:"unique;not null;type:varchar"`
	Phone_number  string `gorm:"unique;not null;type:varchar"`
	Gender        string `gorm:"type:varchar(1)"`
	First_name    string `gorm:"type:varchar"`
	Last_name     string `gorm:"type:varchar"`
	Password_hash string `gorm:"type:varchar"`
}

type Unauthorized_token struct {
	User_id    uint      `gorm:"references:User_account.User_id;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Token      string    `gorm:"type:varchar"`
	Expiration time.Time `gorm:"type:timestamp"`
}

type ErrResponse struct {
	Message string
}

func HandleErr(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func PassMap(pass []byte) string {
	hashed, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)
	HandleErr(err)

	return string(hashed)
}

func ConnectDB() *gorm.DB {
	db, err := gorm.Open("postgres", "host=127.0.0.1 port=5432 user=postgres dbname=postgres password=postgres sslmode=disable")
	HandleErr(err)
	return db
}

func PanicHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			error := recover()
			if error != nil {
				log.Println(error)

				resp := ErrResponse{Message: "Internal server error"}
				json.NewEncoder(w).Encode(resp)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func IsEmailValid(email string) bool {
	emailPattern := regexp.MustCompile(`^[A-Za-z0-9]+[@]+[A-Za-z0-9]+[.]+[A-Za-z]+$`)
	if !emailPattern.MatchString(email) || len(email) > 50 {
		return false
	}
	return true
}

func IsPhoneValid(phone_number string) bool {
	phonePattern := regexp.MustCompile(`^[0-9]{11}$`)
	if !phonePattern.MatchString(phone_number) {
		return false
	}
	return true
}

func IsGenderValid(gender string) bool {
	if !(gender == "F" || gender == "M") {
		return false
	}
	return true
}

func IsNamesValid(f_name string, l_name string) bool {
	namePattern := regexp.MustCompile(`^[A-Za-z]+$`)
	if !namePattern.MatchString(f_name) || !namePattern.MatchString(l_name) {
		return false
	}
	return true
}

func IsPassvalid(pass string) bool {
	passPattern := regexp.MustCompile(`^\S{8,}$`)
	if !passPattern.MatchString(pass) {
		return false
	}
	return true
}

func IsEmail(emailOrPhone string) bool {
	emailPattern := regexp.MustCompile(`^[A-Za-z0-9]+[@]+[A-Za-z0-9]+[.]+[A-Za-z]+$`)
	if emailPattern.MatchString(emailOrPhone) {
		return true
	} else {
		return false
	}
}
