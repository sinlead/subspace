package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	httprouter "github.com/julienschmidt/httprouter"
)

type CustomRequest struct {
	Email string `json:"username"`
	Key   string `json:"key"`
}

type CustomResponse struct {
	Status  int
	Message string
}

var (
	secretKey = os.Getenv("SECRET_KEY")
)

func Delete(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var body CustomRequest

	err := decode(r, &body)

	if err != nil {
		response(http.StatusInternalServerError, err.Error(), w)
		return
	}

	if !secureCompare(body.Key, secretKey) {
		response(http.StatusUnauthorized, "Unauthorized", w)
		return
	}

	user, err := config.FindUserByEmail(body.Email)

	if err != nil {
		response(http.StatusNotFound, "user not found", w)
		return
	}

	for _, profile := range config.ListProfilesByUser(user.ID) {
		if err := deleteProfile(profile); err != nil {
			response(http.StatusInternalServerError, fmt.Sprintf("delete profile failed: %s", err), w)
			return
		}
	}

	if err := config.DeleteUser(user.ID); err != nil {
		response(http.StatusInternalServerError, fmt.Sprintf("delete user failed: %s", err), w)
		return
	}

	response(http.StatusOK, fmt.Sprintf("%s deleted successfully", user.Email), w)
}

func secureCompare(given string, actual string) bool {
	if subtle.ConstantTimeEq(int32(len(given)), int32(len(actual))) == 1 {
		return subtle.ConstantTimeCompare([]byte(given), []byte(actual)) == 1
	} else {
		/* Securely compare actual to itself to keep constant time, but always return false */
		return subtle.ConstantTimeCompare([]byte(actual), []byte(actual)) == 1 && false
	}
}

func response(status int, message string, w http.ResponseWriter) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	r := CustomResponse{Status: status, Message: message}
	json.NewEncoder(w).Encode(r)
}

func decode(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return errors.New("invalid body")
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return err
	}
	return nil
}
