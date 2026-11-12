package audit

import (
	"sync"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/redact"
)

type Log struct {
	mu     sync.Mutex
	events []model.AuditEvent
	seq    int
}

func New() *Log { return &Log{} }

func (l *Log) Add(event model.AuditEvent) model.AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	event.ID = "aud-" + pad(l.seq)
	event.Detail = redact.Secret(event.Detail)
	event.Outcome = redact.Secret(event.Outcome)
	l.events = append(l.events, event)
	return event
}

func (l *Log) Events() []model.AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]model.AuditEvent(nil), l.events...)
}

func pad(n int) string {
	text := itoa(n)
	for len(text) < 4 {
		text = "0" + text
	}
	return text
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
