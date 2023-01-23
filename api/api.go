package api

import (
	"encoding/json"

	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"mahsa_airline.com/go-auth-backend/users"
	"mahsa_airline.com/go-auth-backend/utils"
)

type Login struct {
	EmailOrPhone string
	Password     string
}

type Register struct {
	Email        string
	Phone_number string
	Gender       string
	First_name   string
	Last_name    string
	Password     string
}

func signin(write http.ResponseWriter, read *http.Request) {
	body, err1 := ioutil.ReadAll(read.Body)
	utils.HandleErr(err1)

	var formattedBody Login
	err2 := json.Unmarshal(body, &formattedBody)
	utils.HandleErr(err2)

	login := users.Signin(formattedBody.EmailOrPhone, formattedBody.Password)

	resp := login
	json.NewEncoder(write).Encode(resp)
	write.WriteHeader(http.StatusCreated)
}

func signup(write http.ResponseWriter, read *http.Request) {
	body, err1 := ioutil.ReadAll(read.Body)
	utils.HandleErr(err1)

	var formattedBody Register
	err2 := json.Unmarshal(body, &formattedBody)
	utils.HandleErr(err2)

	register := users.Signup(formattedBody.Email, formattedBody.Phone_number, formattedBody.Gender,
		formattedBody.First_name, formattedBody.Last_name, formattedBody.Password)

	resp := register
	json.NewEncoder(write).Encode(resp)
	write.WriteHeader(http.StatusCreated)
}

func RunApi() {
	httpReq := mux.NewRouter()
	httpReq.Use(utils.PanicHandler)
	httpReq.HandleFunc("/signin", signin).Methods("POST")
	httpReq.HandleFunc("/signup", signup).Methods("POST")
	//router.HandleFunc("/user/{id}", getUser).Methods("GET")
	print("App is working on port :8888\n")
	log.Fatal(http.ListenAndServe(":8888", httpReq))
}
