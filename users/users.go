package users

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
	"mahsa_airline.com/go-auth-backend/utils"
)

func generateToken(user *utils.User_account) string {
	tokenContent := jwt.MapClaims{
		"user_email": user.Email,
		"expiry":     time.Now().Add(time.Minute * 30).Unix(),
	}
	jwtToken := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tokenContent)
	token, err := jwtToken.SignedString([]byte("TokenPassword"))
	utils.HandleErr(err)

	return token
}

func Signup(email string, phone_number string, gender string,
	f_name string, l_name string, pass string) map[string]interface{} {
	db := utils.ConnectDB()
	user := &utils.User_account{}
	if db.Where("email = ? ", email).First(&user).RecordNotFound() && db.Where("phone_number = ? ", phone_number).First(&user).RecordNotFound() {
		if !utils.IsEmailValid(email) {
			return handleSignup(db, "Invalid email.")
		} else if !utils.IsPhoneValid(phone_number) {
			return handleSignup(db, "Phone numbers are 11 digits(09121234567).")
		} else if !utils.IsGenderValid(gender) {
			return handleSignup(db, "Gender must be F or M.")
		} else if !utils.IsNamesValid(f_name, l_name) {
			return handleSignup(db, "Names contain only english letters.")
		} else if !utils.IsPassvalid(pass) {
			return handleSignup(db, "Password are atleast 8 characters.")
		} else {
			generatedPassword := utils.PassMap([]byte(pass))
			user := &utils.User_account{Email: email, Phone_number: phone_number, Gender: gender,
				First_name: f_name, Last_name: l_name, Password_hash: generatedPassword}
			db.Create(&user)
			return handleSignup(db, "you are signed up.")
		}
	} else {
		defer db.Close()
		return map[string]interface{}{"message": "user already exists."}
	}

}

func handleSignup(db *gorm.DB, message string) map[string]interface{} {
	defer db.Close()
	return map[string]interface{}{"message": message}
}

func Signin(emailOrPhone string, pass string) map[string]interface{} {
	db := utils.ConnectDB()
	user := &utils.User_account{}

	if utils.IsEmail(emailOrPhone) {
		return handleSignin(db, emailOrPhone, user, pass, true)
	} else if utils.IsPhoneValid(emailOrPhone) {
		return handleSignin(db, emailOrPhone, user, pass, false)
	} else {
		defer db.Close()
		return map[string]interface{}{"message": "invalid inputs"}
	}

}

func handleSignin(db *gorm.DB, emailOrPhone string, user *utils.User_account, pass string, isEmail bool) map[string]interface{} {
	var reqString = ""
	if isEmail {
		reqString = "email = ? "
	} else {
		reqString = "phone_number = ? "
	}
	if db.Where(reqString, emailOrPhone).First(&user).RecordNotFound() {
		if isEmail {
			return map[string]interface{}{"message": "Wrong email"}
		} else {
			return map[string]interface{}{"message": "Wrong phone number"}
		}
	}
	passErr := bcrypt.CompareHashAndPassword([]byte(user.Password_hash), []byte(pass))
	if passErr == bcrypt.ErrMismatchedHashAndPassword && passErr != nil {
		return map[string]interface{}{"message": "Wrong pass"}
	}
	defer db.Close()

	var response = map[string]interface{}{"message": "you are logged in."}
	var token = generateToken(user)
	response["jwt"] = token
	response["email"] = user.Email
	return response
}
