package main

import (
    "encoding/json"
    "net/http"
)

type intelResponse struct {
    Status string `json:"status"`
    Feeds  int    `json:"feeds"`
}

func serveIntel(w http.ResponseWriter, _ *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(intelResponse{
        Status: "ok",
        Feeds:  0,
    })
}
