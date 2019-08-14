package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
)

type User struct {
	ID int `json:"id"`
	Email string `json:"email"`
	Password string `json:"password"`
}

type JWT struct{
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=disable",
		os.Getenv("HOST"), os.Getenv("PORTDB"),
		os.Getenv("USERDB"), os.Getenv("PASSWORD"), os.Getenv("DBNAME"))

	var err error
	db, err = sql.Open("postgres", psqlInfo)
	logFatal(err)

	err = db.Ping()
	logFatal(err)

	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndPoint)).Methods("GET")

	println("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func respondWithError(w http.ResponseWriter, status int, err Error) {
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(err)
}

func responseJSON(w http.ResponseWriter, data interface{}){
	_ = json.NewEncoder(w).Encode(data)
}

func signup(w http.ResponseWriter, r *http.Request){
	var user User
	var errorModel Error
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil{
		fmt.Println(err)
		return
	}

	if user.Email == ""{
		errorModel.Message = "Email is missing"
		respondWithError(w, http.StatusBadRequest, errorModel)
		return
	}

	if user.Password == ""{
		errorModel.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, errorModel)
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
		respondWithError(w, http.StatusInternalServerError, errorModel)
		return
	}

	user.Password = ""

	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)

}

func login(write http.ResponseWriter, request *http.Request){
	_, _ = write.Write([]byte("Sign Up"))
}

func protectedEndPoint(write http.ResponseWriter, request *http.Request){
	_, _ = write.Write([]byte("Protected end point"))
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc{
	return protectedEndPoint
}