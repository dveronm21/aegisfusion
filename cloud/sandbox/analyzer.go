package main

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "os"
    "strings"
    "time"
)

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

func AnalyzeSample(samplePath string, maxReadBytes int64) (*AnalysisResult, error) {
    start := time.Now()

    file, err := os.Open(samplePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    if maxReadBytes <= 0 {
        maxReadBytes = 1024 * 1024
    }

    hasher := sha256.New()
    header := make([]byte, maxReadBytes)
    n, readErr := file.Read(header)
    if readErr != nil && readErr != io.EOF {
        return nil, readErr
    }
    if n > 0 {
        _, _ = hasher.Write(header[:n])
    }

    if _, err := io.Copy(hasher, file); err != nil {
        return nil, err
    }

    hash := hex.EncodeToString(hasher.Sum(nil))
    content := strings.ToLower(string(header[:n]))

    isMalicious := false
    confidence := float32(0.4)
    threatType := "Unknown"
    indicators := []string{}

    if strings.Contains(content, "eicar-standard-antivirus-test-file") {
        isMalicious = true
        confidence = 0.99
        threatType = "EICAR-Test-File"
        indicators = append(indicators, "EICAR test signature")
    }

    suspiciousStrings := []string{
        "ransomware",
        "encrypt",
        "bitcoin",
        "powershell -enc",
        "cmd.exe /c",
        "mimikatz",
    }
    for _, token := range suspiciousStrings {
        if strings.Contains(content, token) {
            isMalicious = true
            if confidence < 0.85 {
                confidence = 0.85
            }
            threatType = "Suspicious"
            indicators = append(indicators, fmt.Sprintf("Contains string: %s", token))
        }
    }

    if n >= 2 && header[0] == 0x4d && header[1] == 0x5a {
        indicators = append(indicators, "PE executable detected")
        if strings.Contains(content, "upx") {
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

    return result, nil
}
