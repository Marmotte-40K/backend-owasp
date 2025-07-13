package pkg

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

func GetLogWriter(logType string) io.Writer {
    date := time.Now().Format("2006-01-02")
    logDir := filepath.Join("logs", logType)
    os.MkdirAll(logDir, 0755)
    filePath := filepath.Join(logDir, fmt.Sprintf("%s-%s.log", logType, date))
    f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Printf("Could not open log file %s: %v", filePath, err)
        return os.Stdout
    }
    return io.MultiWriter(os.Stdout, f)
}
