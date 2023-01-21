package migrations

import (
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"mahsa_airline.com/go-auth-backend/utils"
)

// for test
func createAccounts() {
	db := utils.ConnectDB()

	generatedPassword := utils.PassMap([]byte("1234"))
	user := &utils.User_account{Email: "s2ad@gmail.com", Phone_number: "090248225",
		Gender: "M", First_name: "ccc", Last_name: "vvv", Password_hash: generatedPassword}
	db.Create(&user)

	user2 := &utils.User_account{Email: "s2ssad@gmail.com", Phone_number: "09024548225",
		Gender: "M", First_name: "ccc", Last_name: "vvv", Password_hash: generatedPassword}
	db.Create(&user2)

	//token := &utils.Unauthorized_token{Token: "asdf"}
	//db.Create(&token)

	defer db.Close()
}

func Migrate() {
	user_account := &utils.User_account{}
	unauthorized_token := &utils.Unauthorized_token{}
	db := utils.ConnectDB()
	db.AutoMigrate(&user_account, &unauthorized_token)
	defer db.Close()
	createAccounts()
}
