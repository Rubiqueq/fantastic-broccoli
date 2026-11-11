// Copy this file to server/queue_adapter.go in the existing Rubika SAF source.
// The existing server/main.go must call attachQueueEndpoints(mux) after
// registering the pre-existing /health, /login/send-code and /login/verify handlers.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"rubikasaf/rubingo"
	"rubikasaf/scheduler"
)

var safeImageID = regexp.MustCompile(`^[a-f0-9]{64}\.(jpg|png)$`)

func queueDataDir() string {
	d := os.Getenv("QUEUE_DATA_DIR")
	if d == "" {
		d = "/data"
	} // Mount a persistent Railway volume here.
	return d
}

func sendScheduledMessage(ctx context.Context, row scheduler.Recipient) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", scheduler.PreSend("context_cancelled_before_provider_call")
	}
	if !row.OptIn || row.ConsentSource == "" {
		return "", scheduler.PreSend("recipient_has_no_verifiable_opt_in")
	}
	app.Lock()
	defer app.Unlock()
	if !app.authenticated || app.client == nil {
		return "", scheduler.PreSend("rubika_login_required")
	}
	if time.Since(app.lastSent) < 30*time.Second {
		return "", scheduler.WaitUntil(app.lastSent.Add(30*time.Second), "server_rate_limit_wait")
	}
	guid := strings.TrimSpace(row.RecipientGUID)
	if guid == "" {
		p := normalizePhone(row.Phone)
		if !phoneFormat.MatchString(p) {
			return "", scheduler.PreSend("invalid_phone")
		}
		// Unofficial API; must be validated against Rubika during real device testing.
		lookup, err := app.client.Builder("addAddressBook", false, true, map[string]interface{}{
			"phone": p, "first_name": "Rubika SAF", "last_name": "",
		})
		if err != nil {
			return "", scheduler.PreSend("recipient_resolution_failed: " + err.Error())
		}
		guid = locateGUID(lookup.Data)
	}
	if !guidFormat.MatchString(guid) {
		return "", scheduler.PreSend("recipient_guid_unresolved")
	}
	opts := rubingo.SendMessageOptions{ObjectGUID: guid, Text: row.Text}
	if row.ImageRef != "" {
		if !safeImageID.MatchString(row.ImageRef) {
			return "", scheduler.PreSend("invalid_image_id")
		}
		path := filepath.Join(queueDataDir(), "media", row.ImageRef)
		content, err := os.ReadFile(path)
		if err != nil || len(content) == 0 || len(content) > 5<<20 {
			return "", scheduler.PreSend("image_not_available")
		}
		hash := sha256.Sum256(content)
		if hex.EncodeToString(hash[:]) != strings.SplitN(row.ImageRef, ".", 2)[0] {
			return "", scheduler.PreSend("image_content_hash_mismatch")
		}
		opts.FileInline = path
		opts.Type = "Image"
	}
	sent, err := app.client.SendMessage(opts)
	if err != nil {
		return "", fmt.Errorf("provider_send_uncertain: %w", err)
	}
	if sent == nil {
		return "", errors.New("provider_returned_empty_response")
	}
	messageID := strings.TrimSpace(sent.MessageID())
	if messageID == "" {
		return "", errors.New("provider_message_id_missing")
	}
	app.lastSent = time.Now()
	return messageID, nil
}

func attachQueueEndpoints(mux *http.ServeMux) error {
	key := os.Getenv("API_KEY")
	if len(key) < 24 {
		return errors.New("API_KEY minimum length is 24")
	}
	engine, err := scheduler.New(filepath.Join(queueDataDir(), "queue.json"), sendScheduledMessage)
	if err != nil {
		return err
	}
	queueHandler, err := scheduler.Handler(engine, key)
	if err != nil {
		return err
	}
	// The existing ServeMux gives longer exact routes priority; this catches
	// /v1/queue/... and is fail-closed for all other unrecognized paths.
	// Reject starting a queue until the personal account is authenticated.
	mux.Handle("POST /v1/queue/start", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			fail(w, 401, "unauthorized")
			return
		}
		app.Lock()
		loggedIn := app.authenticated && app.client != nil
		app.Unlock()
		if !loggedIn {
			fail(w, 409, "rubika_login_required")
			return
		}
		queueHandler.ServeHTTP(w, r)
	}))
	mux.Handle("/", queueHandler)
	mux.HandleFunc("POST /v1/media/upload", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			fail(w, 401, "unauthorized")
			return
		}
		var body struct {
			Base64 string `json:"base64"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			fail(w, 400, "invalid_payload")
			return
		}
		b, err := base64.StdEncoding.DecodeString(body.Base64)
		if err != nil || len(b) == 0 || len(b) > 5<<20 {
			fail(w, 400, "invalid_size_or_encoding")
			return
		}
		ct := http.DetectContentType(b)
		ext := ""
		switch ct {
		case "image/jpeg":
			ext = "jpg"
		case "image/png":
			ext = "png"
		default:
			fail(w, 415, "only_jpeg_png")
			return
		}
		digest := sha256.Sum256(b)
		id := hex.EncodeToString(digest[:]) + "." + ext
		dir := filepath.Join(queueDataDir(), "media")
		if err := os.MkdirAll(dir, 0700); err != nil {
			fail(w, 503, "storage_unavailable")
			return
		}
		path := filepath.Join(dir, id)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			temp, err := os.CreateTemp(dir, ".rubika-media-*.tmp")
			if err != nil {
				fail(w, 503, "media_storage_failed")
				return
			}
			defer os.Remove(temp.Name())
			if err = temp.Chmod(0600); err != nil {
				temp.Close()
				fail(w, 503, "media_storage_failed")
				return
			}
			if _, err = temp.Write(b); err != nil {
				temp.Close()
				fail(w, 503, "media_storage_failed")
				return
			}
			if err = temp.Sync(); err != nil {
				temp.Close()
				fail(w, 503, "media_storage_failed")
				return
			}
			if err = temp.Close(); err != nil {
				fail(w, 503, "media_storage_failed")
				return
			}
			if err = os.Rename(temp.Name(), path); err != nil {
				fail(w, 503, "media_storage_failed")
				return
			}
		} else if err != nil {
			fail(w, 503, "media_storage_failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"image_ref": id})
	})
	go engine.Run(context.Background(), func(err error) {
		// Errors here concern storage / scheduler; no OTP, API key or body logging.
		log.Printf("queue_engine_error: %T", err)
	})
	return nil
}
