package scheduler

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Handler exposes a private management API. The caller must terminate HTTPS
// and supply a high-entropy key via the environment; never embed it in APKs.
func Handler(engine *Engine, apiKey string) (http.Handler, error) {
	if len(apiKey) < 24 {
		return nil, errors.New("API key too short")
	}
	mux := http.NewServeMux()
	respond := func(w http.ResponseWriter, status int, v interface{}) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	require := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			provided := r.Header.Get("X-API-Key")
			if len(provided) != len(apiKey) || subtle.ConstantTimeCompare([]byte(provided), []byte(apiKey)) != 1 {
				respond(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			next(w, r)
		}
	}
	post := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			respond(w, 405, map[string]string{"error": "POST required"})
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v1/queue", require(func(w http.ResponseWriter, r *http.Request) { respond(w, 200, engine.Status()) }))
	mux.HandleFunc("POST /v1/queue/plan", require(func(w http.ResponseWriter, r *http.Request) {
		if !post(w, r) {
			return
		}
		var q struct {
			StartAt      time.Time   `json:"start_at"`
			DelaySeconds int         `json:"delay_seconds"`
			Rows         []Recipient `json:"rows"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 3<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&q); err != nil {
			respond(w, 400, map[string]string{"error": "invalid_plan_json"})
			return
		}
		snap, err := engine.Replace(q.Rows, q.StartAt, q.DelaySeconds)
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, snap)
	}))
	mux.HandleFunc("POST /v1/queue/start", require(func(w http.ResponseWriter, r *http.Request) {
		if !post(w, r) {
			return
		}
		if err := engine.Start(); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, engine.Status())
	}))
	mux.HandleFunc("POST /v1/queue/pause", require(func(w http.ResponseWriter, r *http.Request) {
		if !post(w, r) {
			return
		}
		if err := engine.Pause(); err != nil {
			respond(w, 500, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, engine.Status())
	}))
	mux.HandleFunc("POST /v1/queue/reconcile", require(func(w http.ResponseWriter, r *http.Request) {
		if !post(w, r) {
			return
		}
		var q struct {
			Index      int    `json:"index"`
			State      string `json:"state"`
			ProviderID string `json:"provider_message_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&q); err != nil {
			respond(w, 400, map[string]string{"error": "invalid_json"})
			return
		}
		if err := engine.Reconcile(q.Index, q.State, q.ProviderID); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, engine.Status())
	}))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]string{"status": "ready", "service": "rubika-saf-queue"})
	})
	// Keep unknown paths inaccessible. Avoid CORS wildcard on secrets.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 404, map[string]string{"error": "not_found", "path_length": strconv.Itoa(len(strings.TrimSpace(r.URL.Path)))})
	})
	return mux, nil
}
