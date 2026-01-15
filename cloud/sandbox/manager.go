package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

type SandboxConfig struct {
    UploadDir    string
    ReportDir    string
    ApiURL       string
    ApiKey       string
    PollInterval time.Duration
    MinAge       time.Duration
    MaxReadBytes int64
}

type SandboxManager struct {
    pool          *VMPool
    config        SandboxConfig
    client        *http.Client
    seen          map[string]struct{}
    mu            sync.Mutex
    reportEnabled bool
}

func NewSandboxManager(pool *VMPool, config SandboxConfig) *SandboxManager {
    return &SandboxManager{
        pool:          pool,
        config:        config,
        client:        &http.Client{Timeout: 15 * time.Second},
        seen:          make(map[string]struct{}),
        reportEnabled: true,
    }
}

func (m *SandboxManager) Start() {
    if err := os.MkdirAll(m.config.UploadDir, 0o755); err != nil {
        log.Printf("[SANDBOX] failed to create upload dir: %v", err)
        return
    }

    if err := os.MkdirAll(m.config.ReportDir, 0o755); err != nil {
        log.Printf("[SANDBOX] failed to create report dir: %v", err)
        m.reportEnabled = false
    }

    m.pool.Start(func(path string) {
        result, err := AnalyzeSample(path, m.config.MaxReadBytes)
        if err != nil {
            log.Printf("[SANDBOX] analyze error: %v", err)
            return
        }
        log.Printf("[SANDBOX] analyzed %s (malicious=%v, score=%.2f)", result.FileHash, result.IsMalicious, result.Score)

        if m.reportEnabled {
            if err := m.saveReport(result); err != nil {
                log.Printf("[SANDBOX] report error: %v", err)
            }
        }

        if m.config.ApiURL != "" {
            if err := m.sendResult(result); err != nil {
                log.Printf("[SANDBOX] push error: %v", err)
            }
        }
    })

    log.Printf("[SANDBOX] watching %s", m.config.UploadDir)
    ticker := time.NewTicker(m.config.PollInterval)
    defer ticker.Stop()

    for {
        m.scanOnce()
        <-ticker.C
    }
}

func (m *SandboxManager) scanOnce() {
    entries, err := os.ReadDir(m.config.UploadDir)
    if err != nil {
        log.Printf("[SANDBOX] scan error: %v", err)
        return
    }

    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }

        name := entry.Name()
        path := filepath.Join(m.config.UploadDir, name)
        info, err := entry.Info()
        if err != nil {
            continue
        }

        if time.Since(info.ModTime()) < m.config.MinAge {
            continue
        }

        hash := name
        if !isHexHash(hash) {
            computed, err := hashFile(path)
            if err != nil {
                continue
            }
            hash = computed
        }

        if m.hasReport(hash) {
            continue
        }

        if !m.markSeen(hash) {
            continue
        }

        if !m.pool.Submit(path) {
            log.Printf("[SANDBOX] queue full, skipping %s", path)
        }
    }
}

func (m *SandboxManager) markSeen(hash string) bool {
    m.mu.Lock()
    defer m.mu.Unlock()
    if _, ok := m.seen[hash]; ok {
        return false
    }
    m.seen[hash] = struct{}{}
    return true
}

func (m *SandboxManager) hasReport(hash string) bool {
    if m.config.ReportDir == "" {
        return false
    }
    reportPath := filepath.Join(m.config.ReportDir, hash+".json")
    if _, err := os.Stat(reportPath); err == nil {
        return true
    }
    return false
}

func (m *SandboxManager) saveReport(result *AnalysisResult) error {
    reportPath := filepath.Join(m.config.ReportDir, result.FileHash+".json")
    payload, err := json.MarshalIndent(result, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(reportPath, payload, 0o644)
}

func (m *SandboxManager) sendResult(result *AnalysisResult) error {
    url := strings.TrimRight(m.config.ApiURL, "/") + "/api/v1/analysis/result"
    body, err := json.Marshal(result)
    if err != nil {
        return err
    }

    req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")
    if m.config.ApiKey != "" {
        req.Header.Set("Authorization", "Bearer "+m.config.ApiKey)
    }

    resp, err := m.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return fmt.Errorf("api returned %s", resp.Status)
    }

    return nil
}
