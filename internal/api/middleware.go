package api

import (
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

type handle func(http.ResponseWriter, *http.Request) error

func (s *Server) errorMiddleware(f handle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)
		if err != nil {
			s.logger.Error("handler", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error: %v", err)
			return
		}
	}
}
