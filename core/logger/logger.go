package logger

import (
	"fmt"
	"sync"
	"time"
)

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

type RingLogger struct {
	mu      sync.RWMutex
	entries []LogEntry
	maxSize int
	onLog   func(LogEntry)
}

var GlobalLogger = NewRingLogger(300)

func NewRingLogger(maxSize int) *RingLogger {
	return &RingLogger{
		entries: make([]LogEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

func (l *RingLogger) SetCallback(cb func(LogEntry)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onLog = cb
}

func (l *RingLogger) Log(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	entry := LogEntry{
		Timestamp: time.Now().Format("15:04:05.000"),
		Level:     level,
		Message:   msg,
	}

	l.mu.Lock()
	if len(l.entries) >= l.maxSize {
		l.entries = l.entries[1:]
	}
	l.entries = append(l.entries, entry)
	cb := l.onLog
	l.mu.Unlock()

	// Also print to console
	fmt.Printf("[%s] [%s] %s\n", entry.Timestamp, level, msg)

	if cb != nil {
		cb(entry)
	}
}

func (l *RingLogger) GetLogs() []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	res := make([]LogEntry, len(l.entries))
	copy(res, l.entries)
	return res
}

func Info(format string, args ...any) {
	GlobalLogger.Log("INFO", format, args...)
}

func Warn(format string, args ...any) {
	GlobalLogger.Log("WARN", format, args...)
}

func Error(format string, args ...any) {
	GlobalLogger.Log("ERROR", format, args...)
}

func Success(format string, args ...any) {
	GlobalLogger.Log("SUCCESS", format, args...)
}
