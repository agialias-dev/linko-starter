package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	pkgerr "github.com/pkg/errors"
	"gopkg.in/natefinch/lumberjack.v2"

	"boot.dev/linko/internal/linkoerr"
)

type LogContext struct {
	Username string
	Error    error
}

type stackTracer interface {
	error
	StackTrace() pkgerr.StackTrace
}

type multiError interface {
	error
	Unwrap() []error
}

type spyReadCloser struct {
	io.ReadCloser
	bytesRead int
}

type spyResponseWriter struct {
	http.ResponseWriter
	bytesWritten int
	statusCode   int
}

type closeFunc func() error

const logContextKey contextKey = "log_context"

var sensitiveKeys = []string{"password", "user", "key", "apikey", "secret", "pin", "creditcardno"}

func (r *spyReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.bytesRead += n
	return n, err
}

func (w *spyResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += n
	return n, err
}

func (w *spyResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func httpError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	if logCtx, ok := ctx.Value(logContextKey).(*LogContext); ok {
		logCtx.Error = err
	}
	if status == 401 || status == 403 || status >= 500 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	http.Error(w, err.Error(), status)
}

func redactIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.x", ip4[0], ip4[1], ip4[2])
	}
	return ip.String()
}

func initializeLogger(logFile string) (*slog.Logger, closeFunc, error) {
	handlers := []slog.Handler{
		tint.NewHandler(os.Stderr, &tint.Options{
			NoColor:     !(isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())),
			Level:       slog.LevelDebug,
			ReplaceAttr: replaceAttr,
		}),
	}

	closers := []closeFunc{}

	if logFile != "" {
		logger := &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    1,
			MaxAge:     28,
			MaxBackups: 10,
			LocalTime:  false,
			Compress:   true,
		}
		close := func() error {
			if err := logger.Close(); err != nil {
				return fmt.Errorf("failed to close log file: %w", err)
			}
			return nil
		}
		handlers = append(handlers, slog.NewJSONHandler(logger, &slog.HandlerOptions{
			Level:       slog.LevelInfo,
			ReplaceAttr: replaceAttr,
		}))
		closers = append(closers, close)
	}
	closer := func() error {
		var errs []error
		for _, close := range closers {
			if err := close(); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	return slog.New(slog.NewMultiHandler(handlers...)), closer, nil
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {

	if slices.Contains(sensitiveKeys, a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}

	if a.Value.Kind() == slog.KindString {
		if u, err := url.Parse(a.Value.String()); err == nil {
			if u.User != nil {
				u.User = url.UserPassword("[REDACTED]", "[REDACTED]")
				return slog.String(a.Key, u.String())
			}
		}
	}

	if a.Key == "error" {
		err, ok := a.Value.Any().(error)
		if !ok {
			return a
		}

		if multiErr, ok := errors.AsType[multiError](err); ok {
			var errAttrs []slog.Attr
			for i, e := range multiErr.Unwrap() {
				errAttrs = append(errAttrs, slog.GroupAttrs(fmt.Sprintf("error_%d", i+1), extractErrorAttrs(e)...))
			}
			return slog.GroupAttrs("errors", errAttrs...)
		}

		return slog.GroupAttrs("error", extractErrorAttrs(err)...)
	}
	return a
}

func extractErrorAttrs(err error) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("message", err.Error()),
	}

	attrs = append(attrs, linkoerr.Attrs(err)...)

	if stackErr, ok := errors.AsType[stackTracer](err); ok {
		attrs = append(attrs, slog.Attr{
			Key:   "stack_trace",
			Value: slog.StringValue(fmt.Sprintf("%+v", stackErr.StackTrace())),
		})
	}
	return attrs
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			logCtx := &LogContext{}
			ctx := context.WithValue(r.Context(), logContextKey, logCtx)
			r = r.WithContext(ctx)
			spyReader := &spyReadCloser{ReadCloser: r.Body}
			r.Body = spyReader
			spyWriter := &spyResponseWriter{ResponseWriter: w}

			next.ServeHTTP(spyWriter, r)

			reqAttrs := []slog.Attr{slog.String("request_id", spyWriter.Header().Get("X-Request-ID"))}
			if logCtx.Username != "" {
				reqAttrs = append(reqAttrs, slog.String("user", logCtx.Username))
			}
			reqAttrs = append(reqAttrs,
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("client_ip", redactIP(r.RemoteAddr)),
				slog.Duration("duration", time.Since(start)),
				slog.Int("request_body_bytes", spyReader.bytesRead),
				slog.Int("response_status", spyWriter.statusCode),
				slog.Int("response_body_bytes", spyWriter.bytesWritten),
			)

			if logCtx.Error != nil {
				reqAttrs = append(reqAttrs, slog.Any("error", logCtx.Error))
			}

			logger.LogAttrs(r.Context(), slog.LevelInfo, "Served request", reqAttrs...)
		})
	}
}
