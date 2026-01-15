package main

import (
    "log"
    "net/http"
    "time"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/health", health)
    mux.HandleFunc("/api/intel", serveIntel)

    server := &http.Server{
        Addr:              ":9090",
        Handler:           mux,
        ReadHeaderTimeout: 5 * time.Second,
    }

    log.Println("[THREAT] listening on :9090")
    if err := server.ListenAndServe(); err != nil {
        log.Fatal(err)
    }
}
