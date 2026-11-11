package scheduler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalization(t *testing.T) {
	cases := map[string]string{"۰۹۱۲-۳۴۵ ۶۷۸۹": "989123456789", "+989123456789": "989123456789", "00989123456789": "989123456789"}
	for input, want := range cases {
		if got := NormalizePhone(input); got != want {
			t.Errorf("%q => %q, want %q", input, got, want)
		}
	}
}

func makeEngine(t *testing.T, send Sender) (*Engine, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "queue.json")
	e, err := New(p, send)
	if err != nil {
		t.Fatal(err)
	}
	return e, p
}
func TestDedupConsentAndDelay(t *testing.T) {
	calls := 0
	e, _ := makeEngine(t, func(context.Context, Recipient) (string, error) { calls++; return "m123", nil })
	now := time.Now().UTC().Add(10 * time.Second)
	rows := []Recipient{{Phone: "09123456789", Text: "hi", OptIn: true, ConsentSource: "web_form"}, {Phone: "+989123456789", Text: "dup", OptIn: true, ConsentSource: "web_form"}, {Phone: "09111111111", Text: "not opted in", OptIn: false}}
	s, err := e.Replace(rows, now, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rows) != 2 || s.Rows[1].State != Skipped {
		t.Fatalf("bad dedup/consent: %+v", s)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if did, _ := e.Tick(context.Background(), now.Add(-time.Second)); did {
		t.Fatal("sent too early")
	}
	if did, _ := e.Tick(context.Background(), now); !did {
		t.Fatal("expected send")
	}
	if calls != 1 || e.Status().Rows[0].ProviderID != "m123" {
		t.Fatal("bad send")
	}
	if e.Status().NextAt.Sub(now) != 60*time.Second {
		t.Fatal("wrong interval")
	}
	if did, _ := e.Tick(context.Background(), now.Add(60*time.Second)); did {
		t.Fatal("should be done after skipped row")
	}
	if e.Status().StopReason != "completed" {
		t.Fatal("not completed")
	}
}
func TestCrashDuringSendingPreventsRetry(t *testing.T) {
	now := time.Now().UTC().Add(10 * time.Second)
	e, path := makeEngine(t, func(context.Context, Recipient) (string, error) { return "", errors.New("connection timeout") })
	if _, err := e.Replace([]Recipient{{Phone: "09121111111", Text: "hello", OptIn: true, ConsentSource: "consent_record"}}, now, 30); err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if did, err := e.Tick(context.Background(), now); !did || err != nil {
		t.Fatalf("tick: %v %v", did, err)
	}
	if e.Status().Rows[0].State != Uncertain {
		t.Fatal("should halt uncertain sends")
	}
	if err := e.Start(); err == nil {
		t.Fatal("uncertain send must not be retried")
	}
	restored, err := New(path, func(context.Context, Recipient) (string, error) { t.Fatal("must not send"); return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status().Rows[0].State != Uncertain || restored.Status().Active {
		t.Fatal("restore must pause")
	}
}
func TestPersistentQueueIsPrivate(t *testing.T) {
	e, path := makeEngine(t, func(context.Context, Recipient) (string, error) { return "ok", nil })
	if _, err := e.Replace([]Recipient{{Phone: "09120000000", Text: "hello", OptIn: true, ConsentSource: "record"}}, time.Now().UTC(), 30); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0600 {
		t.Fatalf("queue file permissions: %o", stat.Mode().Perm())
	}
}
func TestRejectInvalid(t *testing.T) {
	e, _ := makeEngine(t, func(context.Context, Recipient) (string, error) { return "ok", nil })
	now := time.Now().UTC()
	if _, err := e.Replace([]Recipient{{Phone: "123", Text: "bad", OptIn: true, ConsentSource: "record"}}, now, 60); err == nil {
		t.Fatal("invalid phone accepted")
	}
	if _, err := e.Replace([]Recipient{{Phone: "09120000000", Text: "hello", OptIn: true, ConsentSource: "record"}}, now, 1); err == nil {
		t.Fatal("too fast accepted")
	}
}

func TestReconcileAfterUncertain(t *testing.T) {
	now := time.Now().UTC().Add(20 * time.Second)
	e, _ := makeEngine(t, func(context.Context, Recipient) (string, error) { return "", errors.New("timeout") })
	_, err := e.Replace([]Recipient{{Phone: "09128889999", Text: "message", OptIn: true, ConsentSource: "signed form"}}, now, 45)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Start(); err != nil {
		t.Fatal(err)
	}
	_, err = e.Tick(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Reconcile(0, Submitted, ""); err == nil {
		t.Fatal("must require observed provider message ID")
	}
	if err = e.Reconcile(0, Submitted, "m123"); err != nil {
		t.Fatal(err)
	}
	state := e.Status()
	if state.Rows[0].State != Submitted || state.Position != 1 {
		t.Fatalf("bad reconciliation: %+v", state)
	}
}

func TestPreSendFailureCanResumeWithoutDuplication(t *testing.T) {
	now := time.Now().UTC().Add(20 * time.Second)
	attempts, providerCalls := 0, 0
	e, path := makeEngine(t, func(context.Context, Recipient) (string, error) {
		attempts++
		if attempts == 1 {
			return "", PreSend("rubika_login_required")
		}
		providerCalls++
		return "provider-id-1", nil
	})
	_, err := e.Replace([]Recipient{{Phone: "09125556677", Text: "hello", OptIn: true, ConsentSource: "form"}}, now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if did, err := e.Tick(context.Background(), now); !did || err != nil {
		t.Fatalf("tick=%v err=%v", did, err)
	}
	s := e.Status()
	if s.Rows[0].State != Pending || s.Position != 0 || s.Active || !s.Paused || providerCalls != 0 {
		t.Fatalf("before-send failure must preserve pending with no provider call: %+v", s)
	}
	if err := e.Start(); err != nil {
		t.Fatal("safe failure should be resumable", err)
	}
	if did, err := e.Tick(context.Background(), now.Add(time.Second)); !did || err != nil {
		t.Fatalf("resume: %v %v", did, err)
	}
	if providerCalls != 1 || e.Status().Rows[0].State != Submitted {
		t.Fatal("safe retry did not submit once")
	}
	state, err := New(path, func(context.Context, Recipient) (string, error) {
		t.Fatal("duplicate send after restart")
		return "", nil
	})
	if err != nil || state.Status().Rows[0].State != Submitted {
		t.Fatal("published state not persisted")
	}
}

func TestProviderSendFailureStillUncertain(t *testing.T) {
	now := time.Now().UTC().Add(20 * time.Second)
	e, _ := makeEngine(t, func(context.Context, Recipient) (string, error) { return "", errors.New("provider_response_lost") })
	_, err := e.Replace([]Recipient{{Phone: "09128887766", Text: "hi", OptIn: true, ConsentSource: "verified"}}, now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if e.Status().Rows[0].State != Uncertain {
		t.Fatal("provider failure must block automatic retry")
	}
}

func TestNextSendMeasuredFromProviderCompletion(t *testing.T) {
	start := time.Now().UTC().Add(20 * time.Millisecond)
	e, _ := makeEngine(t, func(context.Context, Recipient) (string, error) {
		time.Sleep(90 * time.Millisecond)
		return "id-1", nil
	})
	_, err := e.Replace([]Recipient{{Phone: "09127778888", Text: "hi", OptIn: true, ConsentSource: "approved"}}, start, 30)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tick(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	s := e.Status()
	if s.NextAt.Sub(start) < 30*time.Second+50*time.Millisecond {
		t.Fatalf("next attempt not delayed from actual provider response: start %v next %v", start, s.NextAt)
	}
}

func TestCannotOverwriteUncertainOrPartialQueue(t *testing.T) {
	now := time.Now().UTC().Add(40 * time.Second)
	e, _ := makeEngine(t, func(context.Context, Recipient) (string, error) {
		return "", errors.New("provider_timed_out")
	})
	rows := []Recipient{{Phone: "09121234567", Text: "hello", OptIn: true, ConsentSource: "record"}}
	if _, err := e.Replace(rows, now, 30); err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	before := e.Status()
	if before.Rows[0].State != Uncertain {
		t.Fatalf("want uncertain: %+v", before)
	}
	if _, err := e.Replace(rows, now.Add(time.Minute), 60); err == nil {
		t.Fatal("silent overwrite of uncertain delivery would permit duplicates")
	}
	after := e.Status()
	if before.JobID != after.JobID || after.Rows[0].State != Uncertain {
		t.Fatal("original evidence must be preserved")
	}
	if err := e.Reconcile(0, Skipped, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Replace(rows, now.Add(2*time.Minute), 60); err != nil {
		t.Fatalf("fully reconciled and terminal queue may be replaced: %v", err)
	}
}

func TestCannotOverwritePartiallySubmittedQueue(t *testing.T) {
	now := time.Now().UTC().Add(20 * time.Second)
	e, _ := makeEngine(t, func(context.Context, Recipient) (string, error) { return "m1", nil })
	rows := []Recipient{
		{Phone: "09121234567", Text: "hello", OptIn: true, ConsentSource: "record"},
		{Phone: "09121234568", Text: "hello", OptIn: true, ConsentSource: "record"},
	}
	if _, err := e.Replace(rows, now, 60); err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err := e.Pause(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Replace(rows, now.Add(2*time.Minute), 60); err == nil {
		t.Fatal("must not drop submitted evidence before remaining row finishes")
	}
}

func TestCompletedScheduleCanBeReplaced(t *testing.T) {
	now := time.Now().UTC().Add(20 * time.Second)
	e, _ := makeEngine(t, func(context.Context, Recipient) (string, error) { return "id123", nil })
	rows := []Recipient{{Phone: "09121234567", Text: "hello", OptIn: true, ConsentSource: "direct"}}
	old, err := e.Replace(rows, now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if e.Status().StopReason != "completed" {
		t.Fatal("expected completed")
	}
	latest, err := e.Replace(rows, now.Add(2*time.Minute), 30)
	if err != nil {
		t.Fatal(err)
	}
	if old.JobID == latest.JobID {
		t.Fatal("new schedule needs new job id")
	}
}

func TestSafeAutomaticRateDelay(t *testing.T) {
	now := time.Now().UTC().Add(10 * time.Second)
	calls := 0
	notBefore := time.Now().UTC().Add(45 * time.Second)
	e, _ := makeEngine(t, func(context.Context, Recipient) (string, error) {
		calls++
		if calls == 1 {
			return "", WaitUntil(notBefore, "server_rate_limit_wait")
		}
		return "new-id", nil
	})
	rows := []Recipient{{Phone: "09121111222", Text: "hello", OptIn: true, ConsentSource: "explicit"}}
	if _, err := e.Replace(rows, now, 30); err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if did, err := e.Tick(context.Background(), now); !did || err != nil {
		t.Fatalf("tick: %v %v", did, err)
	}
	snap := e.Status()
	if !snap.Active || snap.Paused || snap.Rows[0].State != Pending {
		t.Fatalf("rate limit must defer safely, not pause: %+v", snap)
	}
	if snap.NextAt.Before(notBefore) {
		t.Fatalf("next attempt cannot precede rate limit: %v", snap.NextAt)
	}
	if did, err := e.Tick(context.Background(), notBefore.Add(-time.Second)); did || err != nil {
		t.Fatal("sent before minimum delay")
	}
	if did, err := e.Tick(context.Background(), notBefore.Add(time.Second)); !did || err != nil {
		t.Fatalf("later send should succeed: %v %v", did, err)
	}
	if e.Status().Rows[0].State != Submitted || calls != 2 {
		t.Fatalf("unexpected retry state: %+v calls:%d", e.Status(), calls)
	}
}
