package request

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// ctxKey is an unexported type so we don’t collide with other packages’
type ctxKey string

const key ctxKey = "request-id"

// Middleware adds a UUID to every request & response header.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewString()

		// expose it to clients / reverse-proxies
		w.Header().Set("X-Request-ID", id)

		// stash it in the context
		ctx := context.WithValue(r.Context(), key, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FromContext retrieves the request-ID (or "unknown" when absent).
func FromContext(ctx context.Context) string {
	if v, ok := ctx.Value(key).(string); ok {
		return v
	}
	return "unknown"
}