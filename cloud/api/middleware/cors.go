package middleware

import (
    "net/http"
    "os"
    "strings"
)

func CORS(next http.Handler) http.Handler {
    allowed := os.Getenv("AEGIS_CORS_ORIGIN")
    if strings.TrimSpace(allowed) == "" {
        allowed = "http://localhost:5173,http://127.0.0.1:5173"
    }
    allowed = strings.TrimSpace(allowed)
    allowedList := strings.Split(allowed, ",")
    for i, entry := range allowedList {
        allowedList[i] = strings.TrimSpace(entry)
    }

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        allowOrigin := ""
        if allowed == "*" {
            allowOrigin = "*"
        } else if origin != "" {
            for _, entry := range allowedList {
                if entry == origin {
                    allowOrigin = origin
                    break
                }
            }
        }

        if allowOrigin != "" {
            w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
        }
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }

        next.ServeHTTP(w, r)
    })
}
