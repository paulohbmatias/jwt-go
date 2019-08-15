package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/paulohbmatias/jwt-go/driver"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"strings"
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

func init() {
	_ = gotenv.Load()
}

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	db = driver.ConnectDB()

	router := mux.NewRouter()

	port := os.Getenv("PORT")

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndPoint)).Methods("GET")

	fmt.Println("Listening on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
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

func GenerateToken(user User) (string, error){
	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss": "course",
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil{
		log.Fatal(err)
	}

	return tokenString, nil
}

func login(w http.ResponseWriter, r *http.Request){
	var user User
	var jwtModel JWT
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

	password := user.Password

	row := db.QueryRow("select * from users where email=$1", user.Email)
	err = row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil{
		if err == sql.ErrNoRows{
			errorModel.Message = "The user does not exist"
			respondWithError(w, http.StatusBadRequest, errorModel)
			return
		}else{
			log.Fatal(err)
		}
	}

	hashPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashPassword), []byte(password))

	if err != nil{
		errorModel.Message = "Invalid password"
		respondWithError(w, http.StatusUnauthorized, errorModel)
		return
	}

	token, err := GenerateToken(user)
	if err != nil{
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwtModel.Token = token

	responseJSON(w, jwtModel)
}

func protectedEndPoint(write http.ResponseWriter, request *http.Request){
	_, _ = write.Write([]byte("Protected end point"))
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc{
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorModel Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2{
			authToken := bearerToken[1]

			token, err := jwt.Parse(authToken, func(token *jwt.Token) (i interface{}, e error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok{
					return nil, fmt.Errorf("There was error")
				}

				return []byte("secret"), nil
			})
			if err != nil{
				errorModel.Message = err.Error()
				respondWithError(w, http.StatusUnauthorized, errorModel)
				return
			}

			if token.Valid{
				next.ServeHTTP(w, r)
			}else{
				errorModel.Message = "Invalid token"
				respondWithError(w, http.StatusUnauthorized, errorModel)
				return
			}
		}else{
			errorModel.Message = "Invalid token"
			respondWithError(w, http.StatusUnauthorized, errorModel)
			return
		}
	})
}