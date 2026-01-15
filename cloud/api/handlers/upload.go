package handlers

import (
    "encoding/json"
    "net/http"
)

type uploadResponse struct {
    Status string `json:"status"`
}

func UploadSample(w http.ResponseWriter, _ *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(uploadResponse{Status: "queued"})
}
