package main

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "mime/multipart"
    "net/http"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"

    "aegisfusion/cloud/api/middleware"
)

type Database struct {
    mu            sync.RWMutex
    reputation    map[string]*ReputationResponse
    analysisQueue []AnalysisRequest
    results       map[string]*AnalysisResult
    submissions   []SampleSubmission
    events        int
}

type Server struct {
    db             *Database
    startTime      time.Time
    uploadDir      string
    maxUploadBytes int64
    analysisTokens chan struct{}
    analysisMode   string
}

func main() {
    port := envOrDefault("PORT", "8081")
    uploadDir := envOrDefault("AEGIS_UPLOAD_DIR", "./uploads")
    maxUploadMB := envIntOrDefault("AEGIS_MAX_UPLOAD_MB", 50)
    analysisConcurrency := envIntOrDefault("AEGIS_ANALYSIS_CONCURRENCY", 4)
    analysisMode := strings.ToLower(envOrDefault("AEGIS_ANALYSIS_MODE", "internal"))

    if err := os.MkdirAll(uploadDir, 0o755); err != nil {
        log.Fatalf("[API] failed to create upload dir: %v", err)
    }

    server := &Server{
        db: &Database{
            reputation:    map[string]*ReputationResponse{},
            analysisQueue: []AnalysisRequest{},
            results:       map[string]*AnalysisResult{},
            submissions:   []SampleSubmission{},
        },
        startTime:      time.Now(),
        uploadDir:      uploadDir,
        maxUploadBytes: int64(maxUploadMB) * 1024 * 1024,
        analysisTokens: make(chan struct{}, analysisConcurrency),
        analysisMode:   analysisMode,
    }

    initDatabase(server.db)

    mux := http.NewServeMux()
    mux.HandleFunc("/health", server.healthHandler)
    mux.HandleFunc("/api/v1/upload", server.uploadHandler)
    mux.HandleFunc("/api/v1/reputation", server.reputationHandler)
    mux.HandleFunc("/api/v1/analysis/", server.analysisHandler)
    mux.HandleFunc("/api/v1/analysis/result", server.analysisResultHandler)
    mux.HandleFunc("/api/v1/threat-intel", server.threatIntelHandler)
    mux.HandleFunc("/api/v1/stats", server.statsHandler)
    mux.HandleFunc("/api/v1/events", server.eventsHandler)

    handler := middleware.CORS(middleware.Auth(logRequests(mux)))

    httpServer := &http.Server{
        Addr:              ":" + port,
        Handler:           handler,
        ReadHeaderTimeout: 5 * time.Second,
        ReadTimeout:       30 * time.Second,
        WriteTimeout:      30 * time.Second,
        IdleTimeout:       60 * time.Second,
    }

    log.Printf("[API] listening on :%s", port)
    if err := httpServer.ListenAndServe(); err != nil {
        log.Fatal(err)
    }
}

func initDatabase(db *Database) {
    known := []struct {
        hash string
        name string
    }{
        {"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Test-File"},
        {"131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267", "EICAR-Test-File-CRLF"},
        {"8b3f191819931d1f2cef7289239b5f77c00b079847b9c2636e56854d1e5eff71", "EICAR-Test-File-LF"},
    }

    db.mu.Lock()
    defer db.mu.Unlock()
    for _, entry := range known {
        db.reputation[entry.hash] = &ReputationResponse{
            Hash:        entry.hash,
            Reputation:  "malicious",
            Score:       0.98,
            Prevalence:  1,
            FirstSeen:   time.Now().Add(-24 * time.Hour),
            LastSeen:    time.Now(),
            ThreatNames: []string{entry.name},
        }
    }
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
        return
    }

    writeJSON(w, http.StatusOK, map[string]any{
        "status":    "healthy",
        "service":   "Aegis Fusion Cloud API",
        "version":   "1.0.0",
        "timestamp": time.Now().UTC(),
        "uptime":    time.Since(s.startTime).String(),
    })
}

func (s *Server) uploadHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
        return
    }

    r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadBytes)
    if err := r.ParseMultipartForm(s.maxUploadBytes); err != nil {
        writeError(w, http.StatusBadRequest, "invalid multipart form")
        return
    }

    clientID := strings.TrimSpace(r.FormValue("client_id"))
    if clientID == "" {
        writeError(w, http.StatusBadRequest, "client_id is required")
        return
    }

    file, header, err := r.FormFile("file")
    if err != nil {
        writeError(w, http.StatusBadRequest, "file is required")
        return
    }
    defer file.Close()

    tempFile, err := os.CreateTemp(s.uploadDir, "upload-*")
    if err != nil {
        writeError(w, http.StatusInternalServerError, "failed to store upload")
        return
    }

    hash, size, err := writeAndHash(tempFile, file)
    if err != nil {
        _ = tempFile.Close()
        _ = os.Remove(tempFile.Name())
        writeError(w, http.StatusInternalServerError, "failed to process upload")
        return
    }

    if err := tempFile.Close(); err != nil {
        _ = os.Remove(tempFile.Name())
        writeError(w, http.StatusInternalServerError, "failed to store upload")
        return
    }

    finalPath := filepath.Join(s.uploadDir, hash)
    if _, err := os.Stat(finalPath); err == nil {
        _ = os.Remove(tempFile.Name())
    } else if !os.IsNotExist(err) {
        _ = os.Remove(tempFile.Name())
        writeError(w, http.StatusInternalServerError, "failed to store upload")
        return
    } else if err := os.Rename(tempFile.Name(), finalPath); err != nil {
        _ = os.Remove(tempFile.Name())
        writeError(w, http.StatusInternalServerError, "failed to store upload")
        return
    }

    submission := SampleSubmission{
        ClientID:  clientID,
        FileName:  header.Filename,
        FileHash:  hash,
        FileSize:  size,
        Timestamp: time.Now().UTC(),
        Status:    "queued",
        Metadata: Metadata{
            ProcessName: strings.TrimSpace(r.FormValue("process_name")),
        },
    }

    s.db.mu.Lock()
    s.db.submissions = append(s.db.submissions, submission)
    s.db.analysisQueue = append(s.db.analysisQueue, AnalysisRequest{
        FileHash: hash,
        Priority: 5,
        Deep:     true,
    })
    s.db.mu.Unlock()

    if s.analysisMode != "sandbox" {
        go s.analyzeSample(hash, finalPath)
    }

    writeJSON(w, http.StatusOK, map[string]any{
        "success":   true,
        "file_hash": hash,
        "file_size": size,
        "message":   "sample submitted for analysis",
    })
}

func (s *Server) reputationHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
        return
    }

    var query ReputationQuery
    if err := decodeJSON(w, r, 1<<20, &query); err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    hash, err := normalizeHash(query.Hash)
    if err != nil {
        writeError(w, http.StatusBadRequest, "invalid hash")
        return
    }

    s.db.mu.RLock()
    rep, ok := s.db.reputation[hash]
    s.db.mu.RUnlock()

    if !ok {
        rep = &ReputationResponse{
            Hash:       hash,
            Reputation: "unknown",
            Score:      0.5,
            Prevalence: 0,
            FirstSeen:  time.Now().UTC(),
            LastSeen:   time.Now().UTC(),
        }
    }

    writeJSON(w, http.StatusOK, rep)
}

func (s *Server) analysisHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
        return
    }

    hash := strings.TrimPrefix(r.URL.Path, "/api/v1/analysis/")
    hash, err := normalizeHash(hash)
    if err != nil {
        writeError(w, http.StatusBadRequest, "invalid hash")
        return
    }

    s.db.mu.RLock()
    result, ok := s.db.results[hash]
    s.db.mu.RUnlock()

    if ok {
        writeJSON(w, http.StatusOK, result)
        return
    }

    if s.isInQueue(hash) {
        writeJSON(w, http.StatusOK, map[string]any{
            "status":  "pending",
            "message": "analysis in progress",
        })
        return
    }

    writeError(w, http.StatusNotFound, "analysis not found")
}

func (s *Server) analysisResultHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
        return
    }

    var result AnalysisResult
    if err := decodeJSON(w, r, 2<<20, &result); err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    hash, err := normalizeHash(result.FileHash)
    if err != nil {
        writeError(w, http.StatusBadRequest, "invalid hash")
        return
    }
    result.FileHash = hash
    if result.Analyzed.IsZero() {
        result.Analyzed = time.Now().UTC()
    }

    s.storeResult(&result)
    s.removeFromQueue(hash)

    writeJSON(w, http.StatusAccepted, map[string]string{
        "status": "stored",
    })
}

func (s *Server) threatIntelHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
        return
    }

    update := ThreatIntelUpdate{
        UpdateID:  fmt.Sprintf("TI-%d", time.Now().Unix()),
        Timestamp: time.Now().UTC(),
        Version:   1,
    }

    s.db.mu.RLock()
    for hash, rep := range s.db.reputation {
        if rep.Reputation == "malicious" {
            update.Hashes = append(update.Hashes, hash)
        }
    }
    s.db.mu.RUnlock()

    update.IPs = []string{
        "45.33.32.156",
        "185.220.101.1",
        "192.42.116.16",
    }
    update.Domains = []string{
        "malware-c2.com",
        "evil-payload.net",
        "ransomware-gate.org",
    }
    update.YaraRules = []string{
        `rule EICAR_Test { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }`,
        `rule Generic_Packer { strings: $upx = "UPX!" condition: $upx }`,
    }

    writeJSON(w, http.StatusOK, update)
}

func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
        return
    }

    s.db.mu.RLock()
    defer s.db.mu.RUnlock()

    knownThreats := 0
    knownClean := 0
    unknown := 0
    for _, rep := range s.db.reputation {
        switch rep.Reputation {
        case "malicious":
            knownThreats++
        case "clean":
            knownClean++
        default:
            unknown++
        }
    }

    response := StatsResponse{
        TotalSubmissions: len(s.db.submissions),
        TotalAnalyzed:    len(s.db.results),
        QueueSize:        len(s.db.analysisQueue),
        KnownThreats:     knownThreats,
        KnownClean:       knownClean,
        UnknownFiles:     unknown,
        DatabaseSize:     len(s.db.reputation),
        EventsReceived:   s.db.events,
        Uptime:           time.Since(s.startTime).String(),
    }

    writeJSON(w, http.StatusOK, response)
}

func (s *Server) eventsHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeError(w, http.StatusMethodNotAllowed, "method not allowed")
        return
    }

    var payload EventPayload
    if err := decodeJSON(w, r, 1<<20, &payload); err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    if strings.TrimSpace(payload.ClientID) == "" {
        writeError(w, http.StatusBadRequest, "client_id is required")
        return
    }

    s.db.mu.Lock()
    s.db.events++
    s.db.mu.Unlock()

    writeJSON(w, http.StatusAccepted, map[string]any{
        "status": "accepted",
    })
}

func (s *Server) analyzeSample(hash string, filePath string) {
    s.analysisTokens <- struct{}{}
    defer func() { <-s.analysisTokens }()

    start := time.Now()

    file, err := os.Open(filePath)
    if err != nil {
        log.Printf("[API] analysis failed: %v", err)
        s.removeFromQueue(hash)
        return
    }
    defer file.Close()

    header := make([]byte, 1024*1024)
    n, _ := file.Read(header)
    content := string(header[:n])

    isMalicious := false
    confidence := float32(0.4)
    threatType := "Unknown"
    indicators := []string{}

    if strings.Contains(content, "EICAR-STANDARD-ANTIVIRUS-TEST-FILE") {
        isMalicious = true
        confidence = 0.99
        threatType = "EICAR-Test-File"
        indicators = append(indicators, "EICAR test signature")
    }

    suspiciousStrings := []string{
        "ransomware",
        "encrypt",
        "bitcoin",
        "cmd.exe /c",
        "powershell -enc",
        "mimikatz",
    }
    lowered := strings.ToLower(content)
    for _, s := range suspiciousStrings {
        if strings.Contains(lowered, s) {
            isMalicious = true
            if confidence < 0.85 {
                confidence = 0.85
            }
            threatType = "Suspicious"
            indicators = append(indicators, fmt.Sprintf("Contains string: %s", s))
        }
    }

    if len(header) >= 2 && header[0] == 0x4d && header[1] == 0x5a {
        indicators = append(indicators, "PE executable detected")
        if strings.Contains(content, "UPX") {
            indicators = append(indicators, "Packed with UPX")
        }
    }

    scanTime := time.Since(start).Milliseconds()
    result := &AnalysisResult{
        FileHash:    hash,
        IsMalicious: isMalicious,
        Confidence:  confidence,
        ThreatType:  threatType,
        Score:       confidence,
        Indicators:  indicators,
        Analyzed:    time.Now().UTC(),
        ScanTimeMs:  scanTime,
    }

    s.storeResult(result)

    s.removeFromQueue(hash)
    log.Printf("[API] analysis complete: %s (malicious=%v, %.0f%%, %dms)", hash, isMalicious, confidence*100, scanTime)
}

func (s *Server) storeResult(result *AnalysisResult) {
    s.db.mu.Lock()
    defer s.db.mu.Unlock()

    s.db.results[result.FileHash] = result

    reputation := "clean"
    if result.IsMalicious {
        reputation = "malicious"
    }

    threatNames := []string{}
    if result.IsMalicious && result.ThreatType != "" {
        threatNames = []string{result.ThreatType}
    }

    s.db.reputation[result.FileHash] = &ReputationResponse{
        Hash:        result.FileHash,
        Reputation:  reputation,
        Score:       result.Confidence,
        Prevalence:  1,
        FirstSeen:   time.Now().UTC(),
        LastSeen:    time.Now().UTC(),
        ThreatNames: threatNames,
    }

    for i := range s.db.submissions {
        if s.db.submissions[i].FileHash == result.FileHash {
            if result.IsMalicious {
                s.db.submissions[i].Status = "malicious"
            } else {
                s.db.submissions[i].Status = "clean"
            }
            break
        }
    }
}

func (s *Server) isInQueue(hash string) bool {
    s.db.mu.RLock()
    defer s.db.mu.RUnlock()
    for _, req := range s.db.analysisQueue {
        if req.FileHash == hash {
            return true
        }
    }
    return false
}

func (s *Server) removeFromQueue(hash string) {
    s.db.mu.Lock()
    defer s.db.mu.Unlock()
    for i, req := range s.db.analysisQueue {
        if req.FileHash == hash {
            s.db.analysisQueue = append(s.db.analysisQueue[:i], s.db.analysisQueue[i+1:]...)
            break
        }
    }
}

func writeAndHash(dst *os.File, src multipart.File) (string, int64, error) {
    hasher := sha256.New()
    writer := io.MultiWriter(dst, hasher)
    size, err := io.Copy(writer, src)
    if err != nil {
        return "", 0, err
    }
    return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, dst interface{}) error {
    r.Body = http.MaxBytesReader(w, r.Body, limit)
    decoder := json.NewDecoder(r.Body)
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(dst); err != nil {
        return errors.New("invalid JSON payload")
    }
    return nil
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
    writeJSON(w, status, map[string]string{"error": message})
}

func normalizeHash(hash string) (string, error) {
    hash = strings.ToLower(strings.TrimSpace(hash))
    if len(hash) != 64 {
        return "", errors.New("invalid hash length")
    }
    for _, c := range hash {
        if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
            return "", errors.New("invalid hash")
        }
    }
    return hash, nil
}

func envOrDefault(key, fallback string) string {
    value := strings.TrimSpace(os.Getenv(key))
    if value == "" {
        return fallback
    }
    return value
}

func envIntOrDefault(key string, fallback int) int {
    value := strings.TrimSpace(os.Getenv(key))
    if value == "" {
        return fallback
    }
    parsed, err := strconv.Atoi(value)
    if err != nil {
        return fallback
    }
    return parsed
}

func logRequests(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        next.ServeHTTP(w, r)
        duration := time.Since(start)
        log.Printf("[API] %s %s %s", r.Method, r.URL.Path, duration.Truncate(time.Millisecond))
    })
}
