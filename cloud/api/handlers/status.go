package handlers

import (
    "encoding/json"
    "net/http"
)

type statusResponse struct {
    SystemStatus string        `json:"system_status"`
    Stats        statusStats   `json:"stats"`
    Threats      []statusThreat `json:"threats"`
}

type statusStats struct {
    Scanned     int    `json:"scanned"`
    Blocked     int    `json:"blocked"`
    Quarantined int    `json:"quarantined"`
    Uptime      string `json:"uptime"`
}

type statusThreat struct {
    ID         int     `json:"id"`
    Time       string  `json:"time"`
    Name       string  `json:"name"`
    File       string  `json:"file"`
    Action     string  `json:"action"`
    Confidence float64 `json:"confidence"`
    Severity   string  `json:"severity"`
}

func Status(w http.ResponseWriter, _ *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(statusResponse{
        SystemStatus: "protected",
        Stats: statusStats{
            Scanned:     0,
            Blocked:     0,
            Quarantined: 0,
            Uptime:      "0d 0h 0m",
        },
        Threats: []statusThreat{},
    })
}
