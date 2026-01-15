package main

import (
    "log"
    "os"
    "strconv"
    "strings"
    "time"
)

func main() {
    config := SandboxConfig{
        UploadDir:    envOrDefault("SANDBOX_UPLOAD_DIR", "./uploads"),
        ReportDir:    envOrDefault("SANDBOX_REPORT_DIR", "./reports"),
        ApiURL:       envOrDefault("SANDBOX_API_URL", ""),
        ApiKey:       envOrDefault("SANDBOX_API_KEY", ""),
        PollInterval: time.Duration(envIntOrDefault("SANDBOX_POLL_MS", 2000)) * time.Millisecond,
        MinAge:       time.Duration(envIntOrDefault("SANDBOX_MIN_AGE_SEC", 2)) * time.Second,
        MaxReadBytes: int64(envIntOrDefault("SANDBOX_MAX_READ_MB", 4)) * 1024 * 1024,
    }

    pool := NewVMPool(envIntOrDefault("SANDBOX_WORKERS", 2))
    manager := NewSandboxManager(pool, config)

    log.Println("[SANDBOX] starting manager")
    manager.Start()
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
