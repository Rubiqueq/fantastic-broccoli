// Package scheduler provides a durable, single-recipient-at-a-time, consent-gated
// schedule for a Rubika client. It does NOT implement Rubika authentication or
// guarantee provider delivery; sender adapters must implement those independently.
package scheduler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	Pending   = "pending"
	Sending   = "sending"
	Submitted = "submitted" // Provider returned a message ID; not a read/delivery receipt.
	Uncertain = "uncertain" // Never retry without reconciliation, to avoid duplicates.
	Skipped   = "skipped"
)

var iranMobile = regexp.MustCompile(`^989[0-9]{9}$`)

// Recipient is one row in a scheduled queue. ImageRef should identify a
// media object stored in a private backend bucket, not an arbitrary file URL.
type Recipient struct {
	Phone         string    `json:"phone"`
	RecipientGUID string    `json:"recipient_guid,omitempty"`
	Text          string    `json:"message"`
	ImageRef      string    `json:"image_ref,omitempty"`
	OptIn         bool      `json:"opt_in"`
	ConsentSource string    `json:"opt_in_source"`
	State         string    `json:"state"`
	ProviderID    string    `json:"provider_message_id,omitempty"`
	Error         string    `json:"error,omitempty"`
	AttemptedAt   time.Time `json:"attempted_at,omitempty"`
}

// Snapshot is the persistent state. UTC timestamps are used everywhere.
type Snapshot struct {
	JobID        string      `json:"job_id"`
	StartAt      time.Time   `json:"start_at"`
	NextAt       time.Time   `json:"next_at"`
	DelaySeconds int         `json:"delay_seconds"`
	Position     int         `json:"position"`
	Active       bool        `json:"active"`
	Paused       bool        `json:"paused"`
	StopReason   string      `json:"stop_reason,omitempty"`
	Rows         []Recipient `json:"rows"`
}

// PreSendError is returned only if the adapter knows that SendMessage has NOT
// been called. Unlike a network/send error, resuming after fixing the cause
// cannot duplicate a provider message.
type PreSendError struct{ Reason string }

func (e *PreSendError) Error() string { return e.Reason }
func PreSend(reason string) error     { return &PreSendError{Reason: reason} }

// WaitUntilError is a recoverable local scheduling restriction. No provider
// send has been attempted. The recipient remains pending and the queue stays
// running, so a brief server-wide rate limit never requires manual START.
type WaitUntilError struct {
	Reason string
	At     time.Time
}

func (e *WaitUntilError) Error() string           { return e.Reason }
func WaitUntil(at time.Time, reason string) error { return &WaitUntilError{At: at, Reason: reason} }

type Sender func(ctx context.Context, row Recipient) (providerMessageID string, err error)

type Engine struct {
	mu       sync.Mutex
	path     string
	sender   Sender
	inFlight bool
	state    Snapshot
}

func NormalizePhone(raw string) string {
	s := strings.TrimSpace(raw)
	replacer := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "", "+", "", "۰", "0", "۱", "1", "۲", "2", "۳", "3", "۴", "4", "۵", "5", "۶", "6", "۷", "7", "۸", "8", "۹", "9", "٠", "0", "١", "1", "٢", "2", "٣", "3", "٤", "4", "٥", "5", "٦", "6", "٧", "7", "٨", "8", "٩", "9")
	s = replacer.Replace(s)
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

func New(path string, sender Sender) (*Engine, error) {
	if path == "" || sender == nil {
		return nil, errors.New("durable path and sender required")
	}
	e := &Engine{path: path, sender: sender}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return e, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &e.state); err != nil {
		return nil, fmt.Errorf("corrupt schedule: %w", err)
	}
	// On process termination we cannot know whether the provider accepted an
	// in-flight request; mark it uncertain rather than sending it again.
	for i := range e.state.Rows {
		if e.state.Rows[i].State == Sending {
			e.state.Rows[i].State = Uncertain
			e.state.Rows[i].Error = "process_restarted_during_send_manual_reconciliation_required"
			e.state.Paused = true
			e.state.StopReason = "uncertain_delivery_after_restart"
		}
	}
	// Do not silently resume an authenticated session after server restart.
	e.state.Active = false
	e.state.Paused = true
	if err := e.saveLocked(); err != nil {
		return nil, err
	}
	return e, nil
}

func randomID() string {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf[:])
}

func (e *Engine) Replace(rows []Recipient, startAt time.Time, delaySeconds int) (Snapshot, error) {
	if startAt.IsZero() || startAt.Before(time.Now().Add(-time.Minute)) {
		return Snapshot{}, errors.New("valid present/future schedule time required")
	}
	if delaySeconds < 30 || delaySeconds > 86400 {
		return Snapshot{}, errors.New("interval must be between 30 and 86400 seconds")
	}
	if len(rows) == 0 || len(rows) > 10000 {
		return Snapshot{}, errors.New("recipient count out of allowed range 1-10000")
	}
	seen := make(map[string]bool)
	unique := make([]Recipient, 0, len(rows))
	for _, row := range rows {
		row.Phone = NormalizePhone(row.Phone)
		if !iranMobile.MatchString(row.Phone) {
			return Snapshot{}, fmt.Errorf("invalid recipient phone: %q", row.Phone)
		}
		if seen[row.Phone] {
			continue
		}
		seen[row.Phone] = true
		if row.ImageRef != "" && !regexp.MustCompile(`^[a-f0-9]{64}\.(jpg|png)$`).MatchString(row.ImageRef) {
			return Snapshot{}, errors.New("invalid image reference")
		}
		if len([]rune(row.Text)) > 4200 {
			return Snapshot{}, errors.New("text exceeds 4200 Unicode characters")
		}
		row.ProviderID, row.Error = "", ""
		row.AttemptedAt = time.Time{}
		if !row.OptIn || strings.TrimSpace(row.ConsentSource) == "" {
			row.State = Skipped
		} else if strings.TrimSpace(row.Text) == "" && row.ImageRef == "" {
			row.State = Skipped
			row.Error = "empty_message_and_image"
		} else {
			row.State = Pending
		}
		unique = append(unique, row)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state.Active || e.inFlight {
		return Snapshot{}, errors.New("cannot replace an active or in-flight queue")
	}
	// A paused queue may already have sent messages. Silently replacing that
	// queue would discard the only durable proof of those attempts and makes
	// accidental duplicate delivery possible. Reconciliation must finish first.
	if e.state.JobID != "" && e.state.StopReason != "completed" {
		for _, old := range e.state.Rows {
			if old.State == Submitted || old.State == Uncertain || old.State == Sending {
				return Snapshot{}, errors.New("existing queue contains attempts; complete/reconcile it before creating a new plan")
			}
		}
	}
	e.state = Snapshot{JobID: randomID(), StartAt: startAt.UTC(), NextAt: startAt.UTC(), DelaySeconds: delaySeconds, Rows: unique, Paused: true}
	err := e.saveLocked()
	return copyState(e.state), err
}

func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, row := range e.state.Rows {
		if row.State == Uncertain {
			return errors.New("manual reconciliation needed before resuming an uncertain recipient")
		}
	}
	if len(e.state.Rows) == 0 {
		return errors.New("no queue loaded")
	}
	e.state.Active = true
	e.state.Paused = false
	e.state.StopReason = ""
	return e.saveLocked()
}

func (e *Engine) Pause() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state.Active = false
	e.state.Paused = true
	return e.saveLocked()
}

func copyState(s Snapshot) Snapshot { s.Rows = append([]Recipient(nil), s.Rows...); return s }
func (e *Engine) Status() Snapshot  { e.mu.Lock(); defer e.mu.Unlock(); return copyState(e.state) }

// Tick processes at most one eligible recipient. It may be invoked by a
// durable server clock, cron, or a background worker. It MUST NOT run in
// parallel with another Tick on the same queue; the state guard ensures this.
func (e *Engine) Tick(ctx context.Context, now time.Time) (bool, error) {
	e.mu.Lock()
	if !e.state.Active || e.state.Paused || e.inFlight || now.Before(e.state.NextAt) {
		e.mu.Unlock()
		return false, nil
	}
	for e.state.Position < len(e.state.Rows) && e.state.Rows[e.state.Position].State == Skipped {
		e.state.Position++
	}
	if e.state.Position >= len(e.state.Rows) {
		e.state.Active = false
		e.state.Paused = true
		e.state.StopReason = "completed"
		err := e.saveLocked()
		e.mu.Unlock()
		return false, err
	}
	i := e.state.Position
	row := e.state.Rows[i]
	if row.State != Pending {
		e.state.Active = false
		e.state.Paused = true
		e.state.StopReason = "unexpected_recipient_state"
		err := e.saveLocked()
		e.mu.Unlock()
		return false, err
	}
	e.inFlight = true
	e.state.Rows[i].State = Sending
	e.state.Rows[i].AttemptedAt = now.UTC()
	if err := e.saveLocked(); err != nil {
		e.state.Rows[i].State = Pending
		e.inFlight = false
		e.mu.Unlock()
		return false, err
	}
	e.mu.Unlock()

	id, sendErr := e.sender(ctx, row)

	e.mu.Lock()
	defer e.mu.Unlock()
	e.inFlight = false
	var wait *WaitUntilError
	if sendErr != nil && errors.As(sendErr, &wait) {
		// Adapter confirms Rubika was not called, so retrying later is safe.
		// Never bring the next attempt forward, and avoid a one-second busy loop.
		e.state.Rows[i].State = Pending
		e.state.Rows[i].Error = wait.Reason
		at := wait.At.UTC()
		if at.Before(time.Now().UTC().Add(time.Second)) {
			at = time.Now().UTC().Add(time.Second)
		}
		if at.After(e.state.NextAt) {
			e.state.NextAt = at
		}
		return true, e.saveLocked()
	}
	var preSend *PreSendError
	if sendErr != nil && errors.As(sendErr, &preSend) {
		// No send attempt reached Rubika. Preserve recipient as Pending and
		// pause until the cause is fixed and START is explicitly pressed.
		e.state.Rows[i].State = Pending
		e.state.Rows[i].Error = preSend.Error()
		e.state.Active = false
		e.state.Paused = true
		e.state.StopReason = "pre_send_failure_resume_after_fix"
		return true, e.saveLocked()
	}
	if sendErr != nil || strings.TrimSpace(id) == "" {
		e.state.Rows[i].State = Uncertain
		if sendErr != nil {
			e.state.Rows[i].Error = sendErr.Error()
		} else {
			e.state.Rows[i].Error = "provider_message_id_missing"
		}
		e.state.Active = false
		e.state.Paused = true
		e.state.StopReason = "uncertain_delivery_requires_review"
		return true, e.saveLocked()
	}
	e.state.Rows[i].State = Submitted
	e.state.Rows[i].ProviderID = id
	e.state.Position = i + 1
	// Delay is measured from the provider response, not the start of the
	// preceding attempt. Otherwise slow network calls can violate the
	// minimum interval and trigger an unnecessary rate-limit pause.
	completedAt := time.Now().UTC()
	if now.After(completedAt) { // keep deterministic future-clock simulation in tests
		completedAt = now.UTC()
	}
	e.state.NextAt = completedAt.Add(time.Duration(e.state.DelaySeconds) * time.Second)
	if e.state.Position >= len(e.state.Rows) {
		e.state.Active = false
		e.state.Paused = true
		e.state.StopReason = "completed"
	}
	return true, e.saveLocked()
}

func (e *Engine) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(e.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(e.state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(e.path)
	temp, err := os.CreateTemp(dir, ".queue-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(b); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), e.path)
}

// Reconcile lets an operator resolve an uncertain recipient only after
// inspecting provider-side message history. Re-sending is deliberately NOT
// supported by this API; use Submitted with the observed provider ID, or
// Skipped after manually determining no further attempt is desired.
func (e *Engine) Reconcile(index int, state, providerID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inFlight || e.state.Active {
		return errors.New("pause all in-flight work first")
	}
	if index < 0 || index >= len(e.state.Rows) || e.state.Rows[index].State != Uncertain {
		return errors.New("row is not uncertain")
	}
	if state != Submitted && state != Skipped {
		return errors.New("only submitted or skipped accepted")
	}
	if state == Submitted && strings.TrimSpace(providerID) == "" {
		return errors.New("observed provider ID required")
	}
	e.state.Rows[index].State = state
	e.state.Rows[index].ProviderID = providerID
	e.state.Rows[index].Error = ""
	if index == e.state.Position {
		e.state.Position++
	}
	e.state.Paused = true
	e.state.Active = false
	e.state.StopReason = "manual_reconciliation_complete_resume_explicitly"
	return e.saveLocked()
}

// Run polls a durable schedule while the process is alive. No duplicate sends
// occur after restart: New() restores the schedule in paused mode and requires
// an explicit Start() following renewed authentication.
func (e *Engine) Run(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if _, err := e.Tick(ctx, now); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
