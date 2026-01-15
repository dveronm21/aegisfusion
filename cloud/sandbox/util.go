package main

import (
    "crypto/sha256"
    "encoding/hex"
    "io"
    "os"
)

func isHexHash(value string) bool {
    if len(value) != 64 {
        return false
    }
    for _, c := range value {
        if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
            return false
        }
    }
    return true
}

func hashFile(path string) (string, error) {
    file, err := os.Open(path)
    if err != nil {
        return "", err
    }
    defer file.Close()

    hasher := sha256.New()
    if _, err := io.Copy(hasher, file); err != nil {
        return "", err
    }
    return hex.EncodeToString(hasher.Sum(nil)), nil
}
