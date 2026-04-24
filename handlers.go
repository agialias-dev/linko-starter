package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"boot.dev/linko/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const shortURLLen = len("http://localhost:8080/") + 6

var (
	redirectsMu sync.Mutex
	redirects   []string
)

//go:embed index.html
var indexPage string

func (s *server) handlerIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	io.WriteString(w, indexPage)
}

func (s *server) handlerLogin(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *server) handlerShortenLink(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(UserContextKey).(string)
	if !ok || user == "" {
		httpError(r.Context(), w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		return
	}
	longURL := r.FormValue("url")
	if longURL == "" {
		httpError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("missing url parameter"))
		return
	}
	u, err := url.Parse(longURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		httpError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid URL: must include scheme (http/https) and host"))
		return
	}
	if err := checkDestination(longURL); err != nil {
		httpError(r.Context(), w, http.StatusBadRequest, fmt.Errorf("invalid target URL: %v", err))
		return
	}
	shortCode, err := s.store.Create(r.Context(), longURL)
	if err != nil {
		httpError(r.Context(), w, http.StatusInternalServerError, fmt.Errorf("failed to shorten URL"))
		return
	}
	s.logger.Info("Successfully generated short code",
		slog.String("short_code", shortCode),
		slog.String("url", longURL))
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, shortCode)
}

func (s *server) handlerRedirect(w http.ResponseWriter, r *http.Request) {
	longURL, err := s.store.Lookup(r.Context(), r.PathValue("shortCode"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpError(r.Context(), w, http.StatusNotFound, fmt.Errorf("not found"))
		} else {
			s.logger.Info("failed to lookup URL",
				"error", err)
			httpError(r.Context(), w, http.StatusInternalServerError, fmt.Errorf("internal server error"))
		}
		return
	}
	_, _ = bcrypt.GenerateFromPassword([]byte(longURL), bcrypt.DefaultCost)
	if err := checkDestination(longURL); err != nil {
		httpError(r.Context(), w, http.StatusBadGateway, fmt.Errorf("destination unavailable"))
		return
	}
	redirectsMu.Lock()
	redirects = append(redirects, strings.Repeat(longURL, 1024))
	redirectsMu.Unlock()

	http.Redirect(w, r, longURL, http.StatusFound)
}

func (s *server) handlerListURLs(w http.ResponseWriter, r *http.Request) {
	codes, err := s.store.List(r.Context())
	if err != nil {
		s.logger.Info("failed to list URLs",
			"error", err)
		httpError(r.Context(), w, http.StatusInternalServerError, fmt.Errorf("failed to list URLs"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(codes)
}

func (s *server) handlerStats(w http.ResponseWriter, _ *http.Request) {
	redirectsMu.Lock()
	snapshot := redirects
	redirectsMu.Unlock()

	var bytesSaved int
	for _, u := range snapshot {
		bytesSaved += len(u) - shortURLLen
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"redirects":   len(snapshot),
		"bytes_saved": bytesSaved,
	})
}
