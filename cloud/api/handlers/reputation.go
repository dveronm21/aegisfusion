package handlers

import (
    "encoding/json"
    "net/http"
)

type reputationResponse struct {
    Status     string  `json:"status"`
    Reputation float64 `json:"reputation"`
}

func ReputationLookup(w http.ResponseWriter, _ *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(reputationResponse{
        Status:     "ok",
        Reputation: 0.0,
    })
}
