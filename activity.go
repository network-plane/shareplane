package main

import (
	"fmt"
	"sync"
	"time"
)

const activityRingMax = 500

// activityEvent records a UI/API action (browse, list, search) for logs and /api/status.
type activityEvent struct {
	Time   time.Time `json:"time"`
	IP     string    `json:"ip"`
	Kind   string    `json:"kind"`   // browse, list, search
	Detail string    `json:"detail"` // human-readable path or query description
}

var (
	activityLog []activityEvent
	activityMu  sync.Mutex
)

func recordActivity(ip, kind, detail string) {
	activityMu.Lock()
	ev := activityEvent{Time: time.Now().UTC(), IP: ip, Kind: kind, Detail: detail}
	activityLog = append(activityLog, ev)
	if len(activityLog) > activityRingMax {
		activityLog = activityLog[len(activityLog)-activityRingMax:]
	}
	activityMu.Unlock()

	fmt.Printf("[activity] %s %s — %s — %s\n", ev.Time.Format(time.RFC3339), ip, kind, detail)
	appendServerEvent(kind, ip, detail)
}

func copyActivitySnapshot() []activityEvent {
	activityMu.Lock()
	defer activityMu.Unlock()
	if len(activityLog) == 0 {
		return nil
	}
	out := make([]activityEvent, len(activityLog))
	copy(out, activityLog)
	// Newest first (tail is newest)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func printActivityLog() {
	events := copyActivitySnapshot()
	if len(events) == 0 {
		fmt.Println("Recent UI/API activity: (none)")
		return
	}
	fmt.Println("Recent UI/API activity (newest first):")
	for _, ev := range events {
		fmt.Printf("  %s %s — %s — %s\n", ev.Time.Format(time.RFC3339), ev.IP, ev.Kind, ev.Detail)
	}
}
