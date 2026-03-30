package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const serverEventRingMax = 500

// ServerEvent is a unified event for /api/events and SSE /events (browse, list, search, download, …).
type ServerEvent struct {
	Time   time.Time `json:"time"`
	Type   string    `json:"type"`
	IP     string    `json:"ip,omitempty"`
	Detail string    `json:"detail"`
}

var (
	serverEventLog []ServerEvent
	serverEventMu  sync.Mutex

	sseMu       sync.Mutex
	sseSubs     map[chan ServerEvent]struct{}
	sseInitOnce sync.Once
)

func sseEnsureInit() {
	sseInitOnce.Do(func() {
		sseSubs = make(map[chan ServerEvent]struct{})
	})
}

func sseSubscribe() chan ServerEvent {
	sseEnsureInit()
	ch := make(chan ServerEvent, 64)
	sseMu.Lock()
	sseSubs[ch] = struct{}{}
	sseMu.Unlock()
	return ch
}

func sseUnsubscribe(ch chan ServerEvent) {
	sseMu.Lock()
	delete(sseSubs, ch)
	sseMu.Unlock()
}

func sseBroadcast(ev ServerEvent) {
	sseEnsureInit()
	sseMu.Lock()
	defer sseMu.Unlock()
	for ch := range sseSubs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func appendServerEvent(typ, ip, detail string) {
	serverEventMu.Lock()
	ev := ServerEvent{Time: time.Now().UTC(), Type: typ, IP: ip, Detail: detail}
	serverEventLog = append(serverEventLog, ev)
	if len(serverEventLog) > serverEventRingMax {
		serverEventLog = serverEventLog[len(serverEventLog)-serverEventRingMax:]
	}
	serverEventMu.Unlock()
	sseBroadcast(ev)
}

func copyServerEventsSnapshot() []ServerEvent {
	serverEventMu.Lock()
	defer serverEventMu.Unlock()
	if len(serverEventLog) == 0 {
		return nil
	}
	out := make([]ServerEvent, len(serverEventLog))
	copy(out, serverEventLog)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func handleEventsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(copyServerEventsSnapshot())
}

func handleEventsSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := sseSubscribe()
	defer sseUnsubscribe(ch)

	fmt.Fprintf(w, ": ok\n\n")
	fl.Flush()

	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		case <-tick.C:
			fmt.Fprintf(w, ": ping\n\n")
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
