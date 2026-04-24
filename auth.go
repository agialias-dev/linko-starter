package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"

	pkgerr "github.com/pkg/errors"

	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const UserContextKey contextKey = "user"

var allowedUsers = map[string]string{
	"frodo":   "$2a$10$B6O/n6teuCzpuh66jrUAdeaJ3WvXcxRkzpN0x7H.di9G9e/NGb9Me",
	"samwise": "$2a$10$EWZpvYhUJtJcEMmm/IBOsOGIcpxUnGIVMRiDlN/nxl1RRwWGkJtty",
	// frodo: "ofTheNineFingers"
	// samwise: "theStrong"
	"saruman": "invalidFormat",
}

func (s *server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			httpError(r.Context(), w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		stored, exists := allowedUsers[username]
		if !exists {
			httpError(r.Context(), w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		ok, err := s.validatePassword(password, stored)
		if err != nil {
			s.logger.Error("error validating password",
				slog.String("user", username),
				"error", err)
			httpError(r.Context(), w, http.StatusInternalServerError, fmt.Errorf("internal server error: %w", err))
			return
		}
		if !ok {
			httpError(r.Context(), w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		if logCtx, ok := r.Context().Value(logContextKey).(*LogContext); ok {
			logCtx.Username = username
		}
		r = r.WithContext(context.WithValue(r.Context(), UserContextKey, username))
		next.ServeHTTP(w, r)
	})
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", r.Header.Get("X-Request-ID"))
		if w.Header().Get("X-Request-ID") == "" {
			id := generateRID()
			w.Header().Set("X-Request-ID", id)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) validatePassword(password, stored string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, pkgerr.WithStack(err)
	}
	return true, nil
}

func generateRID() string {
	return rand.Text()
}
