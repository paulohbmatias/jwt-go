package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/paulohbmatias/jwt-go/models"
	user "github.com/paulohbmatias/jwt-go/repository/user"
	"github.com/paulohbmatias/jwt-go/utils"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type Controller struct{}

func (c Controller) Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userModel models.User
		var jwtModel models.JWT
		var errorModel models.Error
		err := json.NewDecoder(r.Body).Decode(&userModel)
		if err != nil{
			fmt.Println(err)
			return
		}

		if userModel.Email == ""{
			errorModel.Message = "Email is missing"
			utils.RespondWithError(w, http.StatusBadRequest, errorModel)
			return
		}

		if userModel.Password == ""{
			errorModel.Message = "Password is missing"
			utils.RespondWithError(w, http.StatusBadRequest, errorModel)
			return
		}

		password := userModel.Password

		userRepo := user.UserRepository{}
		userModel, err = userRepo.Login(db, userModel)

		if err != nil{
			if err == sql.ErrNoRows{
				errorModel.Message = "The userModel does not exist"
				utils.RespondWithError(w, http.StatusBadRequest, errorModel)
				return
			}else{
				log.Fatal(err)
			}
		}

		hashPassword := userModel.Password

		err = bcrypt.CompareHashAndPassword([]byte(hashPassword), []byte(password))

		if err != nil{
			errorModel.Message = "Invalid password"
			utils.RespondWithError(w, http.StatusUnauthorized, errorModel)
			return
		}

		token, err := utils.GenerateToken(userModel)
		if err != nil{
			log.Fatal(err)
		}

		w.WriteHeader(http.StatusOK)
		jwtModel.Token = token

		utils.ResponseJSON(w, jwtModel)
	}
}

func (c Controller) Signup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userModel models.User
		var errorModel models.Error
		err := json.NewDecoder(r.Body).Decode(&userModel)
		if err != nil{
			fmt.Println(err)
			return
		}

		if userModel.Email == ""{
			errorModel.Message = "Email is missing"
			utils.RespondWithError(w, http.StatusBadRequest, errorModel)
			return
		}

		if userModel.Password == ""{
			errorModel.Message = "Password is missing"
			utils.RespondWithError(w, http.StatusBadRequest, errorModel)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(userModel.Password), bcrypt.DefaultCost)

		if err != nil {
			log.Fatal(err)
		}

		userModel.Password = string(hash)

		userRepo := user.UserRepository{}
		userModel, err = userRepo.Signup(db, userModel)

		if err != nil {
			fmt.Println(err)
			errorModel.Message = "Server error."
			utils.RespondWithError(w, http.StatusInternalServerError, errorModel)
			return
		}

		userModel.Password = ""

		w.Header().Set("Content-Type", "application/json")
		utils.ResponseJSON(w, userModel)
	}
}