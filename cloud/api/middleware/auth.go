package middleware

import (
    "net/http"
    "os"
    "strings"
)

func Auth(next http.Handler) http.Handler {
    keys := loadKeys(os.Getenv("AEGIS_API_KEYS"))
    if len(keys) == 0 {
        return next
    }

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodOptions || r.URL.Path == "/health" {
            next.ServeHTTP(w, r)
            return
        }

        token := extractToken(r)
        if token == "" || !keys[token] {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusUnauthorized)
            _, _ = w.Write([]byte(`{"error":"unauthorized"}`))
            return
        }

        next.ServeHTTP(w, r)
    })
}

func loadKeys(raw string) map[string]bool {
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return nil
    }
    tokens := strings.Split(raw, ",")
    result := make(map[string]bool, len(tokens))
    for _, token := range tokens {
        token = strings.TrimSpace(token)
        if token != "" {
            result[token] = true
        }
    }
    return result
}

func extractToken(r *http.Request) string {
    if value := strings.TrimSpace(r.Header.Get("X-API-Key")); value != "" {
        return value
    }
    auth := strings.TrimSpace(r.Header.Get("Authorization"))
    if auth == "" {
        return ""
    }
    if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
        return strings.TrimSpace(auth[7:])
    }
    return ""
}
