package utils

import (
	"encoding/json"
	"fmt"
	"github.com/paulohbmatias/jwt-go/models"
	"log"
	"net/http"
	"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

func RespondWithError(w http.ResponseWriter, status int, err models.Error) {
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(err)
}

func ResponseJSON(w http.ResponseWriter, data interface{}){
	_ = json.NewEncoder(w).Encode(data)
}

func GenerateToken(user models.User) (string, error){
	secret := os.Getenv("SECRET")

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

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc{
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorModel models.Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2{
			authToken := bearerToken[1]

			token, err := jwt.Parse(authToken, func(token *jwt.Token) (i interface{}, e error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok{
					return nil, fmt.Errorf("There was error")
				}

				return []byte(os.Getenv("SECRET")), nil
			})
			if err != nil{
				errorModel.Message = err.Error()
				RespondWithError(w, http.StatusUnauthorized, errorModel)
				return
			}

			if token.Valid{
				next.ServeHTTP(w, r)
			}else{
				errorModel.Message = "Invalid token"
				RespondWithError(w, http.StatusUnauthorized, errorModel)
				return
			}
		}else{
			errorModel.Message = "Invalid token"
			RespondWithError(w, http.StatusUnauthorized, errorModel)
			return
		}
	})
}