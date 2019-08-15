package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/paulohbmatias/jwt-go/driver"
	"github.com/paulohbmatias/jwt-go/models"
	"github.com/paulohbmatias/jwt-go/utils"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
)

var db *sql.DB

func init() {
	_ = gotenv.Load()
}

func main() {
	db = driver.ConnectDB()
	//teste
	router := mux.NewRouter()

	port := os.Getenv("PORT")

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", utils.TokenVerifyMiddleWare(protectedEndPoint)).Methods("GET")

	fmt.Println("Listening on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func signup(w http.ResponseWriter, r *http.Request){
	var user models.User
	var errorModel models.Error
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil{
		fmt.Println(err)
		return
	}

	if user.Email == ""{
		errorModel.Message = "Email is missing"
		utils.RespondWithError(w, http.StatusBadRequest, errorModel)
		return
	}

	if user.Password == ""{
		errorModel.Message = "Password is missing"
		utils.RespondWithError(w, http.StatusBadRequest, errorModel)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		log.Fatal(err)
	}

	user.Password = string(hash)

	stmt := "insert into users (email, password) values($1, $2) RETURNING id;"

	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		fmt.Println(err)
		errorModel.Message = "Server error."
		utils.RespondWithError(w, http.StatusInternalServerError, errorModel)
		return
	}

	user.Password = ""

	w.Header().Set("Content-Type", "application/json")
	utils.ResponseJSON(w, user)

}

func login(w http.ResponseWriter, r *http.Request){
	var user models.User
	var jwtModel models.JWT
	var errorModel models.Error
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil{
		fmt.Println(err)
		return
	}

	if user.Email == ""{
		errorModel.Message = "Email is missing"
		utils.RespondWithError(w, http.StatusBadRequest, errorModel)
		return
	}

	if user.Password == ""{
		errorModel.Message = "Password is missing"
		utils.RespondWithError(w, http.StatusBadRequest, errorModel)
		return
	}

	password := user.Password

	row := db.QueryRow("select * from users where email=$1", user.Email)
	err = row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil{
		if err == sql.ErrNoRows{
			errorModel.Message = "The user does not exist"
			utils.RespondWithError(w, http.StatusBadRequest, errorModel)
			return
		}else{
			log.Fatal(err)
		}
	}

	hashPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashPassword), []byte(password))

	if err != nil{
		errorModel.Message = "Invalid password"
		utils.RespondWithError(w, http.StatusUnauthorized, errorModel)
		return
	}

	token, err := utils.GenerateToken(user)
	if err != nil{
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwtModel.Token = token

	utils.ResponseJSON(w, jwtModel)
}

func protectedEndPoint(write http.ResponseWriter, request *http.Request){
	_, _ = write.Write([]byte("Protected end point"))
}

