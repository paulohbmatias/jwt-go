package main

import (
	"database/sql"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/paulohbmatias/jwt-go/controllers"
	"github.com/paulohbmatias/jwt-go/driver"
	"github.com/paulohbmatias/jwt-go/utils"
	"github.com/subosito/gotenv"
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

	router := mux.NewRouter()

	controller := controllers.Controller{}

	port := os.Getenv("PORT")

	router.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	router.HandleFunc("/login", controller.Login(db)).Methods("POST")
	router.HandleFunc("/protected", utils.TokenVerifyMiddleWare(controller.Protected(db))).Methods("GET")

	fmt.Println("Listening on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

