package main

import "time"

type SampleSubmission struct {
    ClientID    string    `json:"client_id"`
    FileName    string    `json:"file_name"`
    FileHash    string    `json:"file_hash"`
    FileSize    int64     `json:"file_size"`
    Timestamp   time.Time `json:"timestamp"`
    Status      string    `json:"status"`
    Metadata    Metadata  `json:"metadata"`
}

type Metadata struct {
    ProcessName string `json:"process_name"`
    ProcessID   int    `json:"process_id"`
    ParentPID   int    `json:"parent_pid"`
    CommandLine string `json:"command_line"`
    FirstSeen   string `json:"first_seen"`
}

type AnalysisRequest struct {
    FileHash string `json:"file_hash"`
    Priority int    `json:"priority"`
    Deep     bool   `json:"deep_analysis"`
}

type AnalysisResult struct {
    FileHash    string    `json:"file_hash"`
    IsMalicious bool      `json:"is_malicious"`
    Confidence  float32   `json:"confidence"`
    ThreatType  string    `json:"threat_type"`
    Score       float32   `json:"score"`
    Indicators  []string  `json:"indicators"`
    Analyzed    time.Time `json:"analyzed_at"`
    ScanTimeMs  int64     `json:"scan_time_ms"`
}

type ReputationQuery struct {
    Hash string `json:"hash"`
}

type ReputationResponse struct {
    Hash        string    `json:"hash"`
    Reputation  string    `json:"reputation"`
    Score       float32   `json:"score"`
    Prevalence  int64     `json:"prevalence"`
    FirstSeen   time.Time `json:"first_seen"`
    LastSeen    time.Time `json:"last_seen"`
    ThreatNames []string  `json:"threat_names,omitempty"`
}

type ThreatIntelUpdate struct {
    UpdateID  string    `json:"update_id"`
    Timestamp time.Time `json:"timestamp"`
    Hashes    []string  `json:"malicious_hashes"`
    IPs       []string  `json:"malicious_ips"`
    Domains   []string  `json:"malicious_domains"`
    YaraRules []string  `json:"yara_rules"`
    Version   int       `json:"version"`
}

type StatsResponse struct {
    TotalSubmissions int `json:"total_submissions"`
    TotalAnalyzed    int `json:"total_analyzed"`
    QueueSize        int `json:"queue_size"`
    KnownThreats     int `json:"known_threats"`
    KnownClean       int `json:"known_clean"`
    UnknownFiles     int `json:"unknown_files"`
    DatabaseSize     int `json:"database_size"`
    EventsReceived   int `json:"events_received"`
    Uptime           string `json:"uptime"`
}

type EventPayload struct {
    ClientID string      `json:"client_id"`
    Event    interface{} `json:"event"`
}
