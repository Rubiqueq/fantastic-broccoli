package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"rubikasaf/rubingo"
)

type request struct {
	Phone         string `json:"phone"`
	Password      string `json:"password"`
	Code          string `json:"code"`
	Text          string `json:"text"`
	RecipientGUID string `json:"recipient_guid"`
	OptIn         bool   `json:"opt_in"`
}

var app struct {
	sync.Mutex
	client        *rubingo.RubClient
	challenge     *rubingo.SendCodeResult
	account       string
	authenticated bool
	lastSent      time.Time
}

var phoneFormat = regexp.MustCompile(`^989[0-9]{9}$`)
var guidFormat = regexp.MustCompile(`^u0[A-Za-z0-9]{1,126}$`)

func normalizePhone(s string) string {
	s = strings.NewReplacer(" ", "", "-", "", "+", "").Replace(strings.TrimSpace(s))
	if strings.HasPrefix(s, "0098") {
		s = s[2:]
	}
	if strings.HasPrefix(s, "09") {
		s = "98" + s[1:]
	}
	if strings.HasPrefix(s, "9") && len(s) == 10 {
		s = "98" + s
	}
	return s
}
func reply(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
func authorized(r *http.Request) bool {
	key := os.Getenv("API_KEY")
	header := r.Header.Get("X-API-Key")
	return len(key) >= 24 && len(header) == len(key) && subtle.ConstantTimeCompare([]byte(header), []byte(key)) == 1
}
func data(w http.ResponseWriter, r *http.Request) (request, error) {
	var payload request
	if r.Method != http.MethodPost {
		return payload, errors.New("POST required")
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	if err := d.Decode(&payload); err != nil {
		return payload, err
	}
	return payload, nil
}
func locateGUID(x interface{}) string {
	switch obj := x.(type) {
	case map[string]interface{}:
		for k, v := range obj {
			if strings.EqualFold(k, "user_guid") || strings.EqualFold(k, "object_guid") {
				if s, ok := v.(string); ok && guidFormat.MatchString(s) {
					return s
				}
			}
		}
		for _, v := range obj {
			if found := locateGUID(v); found != "" {
				return found
			}
		}
	case []interface{}:
		for _, v := range obj {
			if found := locateGUID(v); found != "" {
				return found
			}
		}
	}
	return ""
}
func main() {
	if len(os.Getenv("API_KEY")) < 24 {
		log.Fatal("API_KEY must have at least 24 chars")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]interface{}{"ok": true, "service": "rubika-saf-scheduler", "provider_login_verified": false})
	})
	mux.HandleFunc("POST /login/send-code", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			fail(w, 401, "unauthorized")
			return
		}
		payload, err := data(w, r)
		if err != nil {
			fail(w, 400, "invalid_json")
			return
		}
		phone := normalizePhone(payload.Phone)
		if !phoneFormat.MatchString(phone) {
			fail(w, 400, "invalid_phone")
			return
		}
		app.Lock()
		defer app.Unlock()
		if app.client != nil {
			app.client.Disconnect()
			app.client = nil
		}
		app.challenge = nil
		app.authenticated = false
		client, err := rubingo.NewClient("rubika_saf", rubingo.WithSessionCallback(func(rubingo.SessionData) {}))
		if err != nil {
			fail(w, 502, "client_init_failed")
			return
		}
		if err = client.Connect(); err != nil {
			fail(w, 502, "connect_failed")
			return
		}
		challenge, err := client.SendCodeExt(phone, payload.Password)
		if err != nil {
			client.Disconnect()
			fail(w, 502, fmt.Sprintf("login_challenge_failed: %s", err.Error()))
			return
		}
		if challenge == nil || challenge.PhoneCodeHash == "" || challenge.TmpSession == "" {
			client.Disconnect()
			fail(w, 502, "login_challenge_incomplete")
			return
		}
		app.client = client
		app.challenge = challenge
		app.account = phone
		reply(w, 200, map[string]string{"status": "OTP_REQUESTED"})
	})
	mux.HandleFunc("POST /login/verify", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			fail(w, 401, "unauthorized")
			return
		}
		payload, err := data(w, r)
		if err != nil {
			fail(w, 400, "invalid_json")
			return
		}
		if len(payload.Code) < 4 || len(payload.Code) > 12 {
			fail(w, 400, "invalid_code")
			return
		}
		app.Lock()
		defer app.Unlock()
		if app.client == nil || app.challenge == nil {
			fail(w, 409, "request_code_first")
			return
		}
		result, err := app.client.SignInExt(payload.Code, app.account, app.challenge.PhoneCodeHash, app.challenge.TmpSession)
		if err != nil {
			fail(w, 502, "signin_failed: "+err.Error())
			return
		}
		if _, err = app.client.ApplySignInResult(result); err != nil {
			fail(w, 502, "session_apply_failed")
			return
		}
		app.authenticated = true
		app.challenge = nil
		reply(w, 200, map[string]string{"status": "AUTHENTICATED"})
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			fail(w, 401, "unauthorized")
			return
		}
		app.Lock()
		defer app.Unlock()
		reply(w, 200, map[string]interface{}{"authenticated": app.authenticated})
	})
	// The queue is server-side and persistent: no fragile Android-only thread.
	if err := attachQueueEndpoints(mux); err != nil {
		log.Fatal(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("Rubika SAF queue started on port %s (no OTP, key, or message-body logging)", port)
	log.Fatal(srv.ListenAndServe())
}
