package api

import (
	"fmt"
	"log"
	"net/http"
)

type handle func(http.ResponseWriter, *http.Request) error

func errorMiddleware(f handle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)
		if err != nil {
			log.Printf("error in handler: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error: %v", err)
			return
		}
	}
}
