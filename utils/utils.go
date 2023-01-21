package utils

import (
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
	db, err := gorm.Open("postgres", "host=127.0.0.1 port=5432 user=postgres dbname=db password=postgres sslmode=disable")
	HandleErr(err)
	return db
}
