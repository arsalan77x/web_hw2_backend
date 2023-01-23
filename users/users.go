package users

import (
	"golang.org/x/crypto/bcrypt"
	"mahsa_airline.com/go-auth-backend/utils"
)

// func giveToken(user *interfaces.User) string {
// 	tokenContent := jwt.MapClaims{
// 		"user_id": user.ID,
// 		"expiry":  time.Now().Add(time.Minute * 60).Unix(),
// 	}
// 	jwtToken := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tokenContent)
// 	token, err := jwtToken.SignedString([]byte("TokenPassword"))
// 	helpers.HandleErr(err)

// 	return token
// }


// func prepareResponse(user *interfaces.User, accounts []interfaces.ResponseAccount, withToken bool) map[string]interface{} {
// 	responseUser := &interfaces.ResponseUser{
// 		ID:       user.ID,
// 		Username: user.Username,
// 		Email:    user.Email,
// 		Accounts: accounts,
// 	}
// 	var response = map[string]interface{}{"message": "all is fine"}

// 	if withToken {
// 		var token = prepareToken(user)
// 		response["jwt"] = token
// 	}
// 	response["data"] = responseUser
// 	return response
// }

func Signup(email string, phone_number string, gender string,
	f_name string, l_name string, pass string) map[string]interface{} {
	db := utils.ConnectDB()
	user := &utils.User_account{}
	if db.Where("email = ? ", email).First(&user).RecordNotFound() && db.Where("phone_number = ? ", phone_number).First(&user).RecordNotFound() {

		if !utils.IsEmailValid(email) {
			defer db.Close()
			return map[string]interface{}{"message": "Invalid email."}
		} else if !utils.IsPhoneValid(phone_number) {
			defer db.Close()
			return map[string]interface{}{"message": "Phone numbers are 11 digits(09121234567)."}
		} else if !utils.IsGenderValid(gender) {
			defer db.Close()
			return map[string]interface{}{"message": "Gender must be F or M."}
		} else if !utils.IsNamesValid(f_name, l_name) {
			defer db.Close()
			return map[string]interface{}{"message": "Names contain only english letters."}
		} else if !utils.IsPassvalid(pass) {
			defer db.Close()
			return map[string]interface{}{"message": "Password are atleast 8 characters."}
		} else {
			generatedPassword := utils.PassMap([]byte(pass))
			user := &utils.User_account{Email: email, Phone_number: phone_number, Gender: gender,
				First_name: f_name, Last_name: l_name, Password_hash: generatedPassword}
			db.Create(&user)
			defer db.Close()
			return map[string]interface{}{"message": "you are signed up."}
		}

	} else {
		defer db.Close()
		return map[string]interface{}{"message": "user already exists."}
	}

}

func Signin(emailOrPhone string, pass string) map[string]interface{} {
	db := utils.ConnectDB()
	user := &utils.User_account{}
	if utils.IsEmail(emailOrPhone) {
		if db.Where("email = ? ", emailOrPhone).First(&user).RecordNotFound() {
			return map[string]interface{}{"message": "Wrong email"}
		}
		passErr := bcrypt.CompareHashAndPassword([]byte(user.Password_hash), []byte(pass))
		if passErr == bcrypt.ErrMismatchedHashAndPassword && passErr != nil {
			return map[string]interface{}{"message": "Wrong pass"}
		}
		defer db.Close()
		return map[string]interface{}{"message": "you are logged in."}
	} else if utils.IsPhoneValid(emailOrPhone) {

		if db.Where("phone_number = ? ", emailOrPhone).First(&user).RecordNotFound() {
			return map[string]interface{}{"message": "Wrong phone number"}
		}
		passErr := bcrypt.CompareHashAndPassword([]byte(user.Password_hash), []byte(pass))
		if passErr == bcrypt.ErrMismatchedHashAndPassword && passErr != nil {
			return map[string]interface{}{"message": "Wrong pass"}
		}
		defer db.Close()
		return map[string]interface{}{"message": "you are logged in."}

	} else {
		defer db.Close()
		return map[string]interface{}{"message": "invalid inputs"}
	}

}
