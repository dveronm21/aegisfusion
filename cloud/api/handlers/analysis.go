package handlers

import (
    "encoding/json"
    "net/http"
)

type analysisResponse struct {
    Status  string `json:"status"`
    Verdict string `json:"verdict"`
}

func RequestAnalysis(w http.ResponseWriter, _ *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(analysisResponse{
        Status:  "ok",
        Verdict: "pending",
    })
}
