package scheduler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAPIRequiresAuthorization(t *testing.T) {
	engine, _ := makeEngine(t, func(context.Context, Recipient) (string, error) { return "ok", nil })
	h, err := Handler(engine, "0123456789abcdefghijklmno")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/queue", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("should require key, got %d", w.Code)
	}
	req.Header.Set("X-API-Key", "0123456789abcdefghijklmno")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("valid authorization: %d", w.Code)
	}
}
func TestAPIPlansConsentAndSchedule(t *testing.T) {
	engine, _ := makeEngine(t, func(context.Context, Recipient) (string, error) { return "ok", nil })
	h, _ := Handler(engine, "0123456789abcdefghijklmno")
	when := time.Now().UTC().Add(90 * time.Second).Format(time.RFC3339)
	body := []byte(`{"start_at":"` + when + `","delay_seconds":60,"rows":[{"phone":"09121234567","message":"سلام","opt_in":true,"opt_in_source":"form"},{"phone":"09123334444","message":"test","opt_in":false}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/queue/plan", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "0123456789abcdefghijklmno")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("plan: %d, %s", w.Code, w.Body.String())
	}
	snap := engine.Status()
	if len(snap.Rows) != 2 || snap.Rows[0].State != Pending || snap.Rows[1].State != Skipped {
		t.Fatalf("consent not enforced: %+v", snap.Rows)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/v1/queue/start", nil)
	req2.Header.Set("X-API-Key", "0123456789abcdefghijklmno")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("start %d %s", w2.Code, w2.Body.String())
	}
}
