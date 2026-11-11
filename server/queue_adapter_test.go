package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateMediaUploadAtomicAndVerified(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("QUEUE_DATA_DIR", dir)
	t.Setenv("API_KEY", "test-secret-api-key-at-least-24-bytes")
	mux := http.NewServeMux()
	if err := attachQueueEndpoints(mux); err != nil {
		t.Fatal(err)
	}
	png := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0}
	body, err := json.Marshal(map[string]string{"base64": base64.StdEncoding.EncodeToString(png)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/media/upload", bytes.NewReader(body))
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != 401 {
		t.Fatalf("no key must be unauthorized, got %d", resp.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/media/upload", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "test-secret-api-key-at-least-24-bytes")
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != 200 {
		t.Fatalf("valid PNG upload: %d %s", resp.Code, resp.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	got := result["image_ref"]
	hash := sha256.Sum256(png)
	want := hex.EncodeToString(hash[:]) + ".png"
	if got != want {
		t.Fatalf("want %s got %s", want, got)
	}
	target := filepath.Join(dir, "media", got)
	stored, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, png) {
		t.Fatal("media changed during upload")
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("private media permissions: %04o", st.Mode().Perm())
	}
	tmp, err := filepath.Glob(filepath.Join(dir, "media", ".rubika-media-*.tmp"))
	if err != nil || len(tmp) != 0 {
		t.Fatalf("leftover partial media: %v %v", tmp, err)
	}
}

func TestRejectNonImageAndUnauthenticatedQueueStart(t *testing.T) {
	t.Setenv("QUEUE_DATA_DIR", t.TempDir())
	t.Setenv("API_KEY", "test-secret-api-key-at-least-24-bytes")
	mux := http.NewServeMux()
	if err := attachQueueEndpoints(mux); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"base64": base64.StdEncoding.EncodeToString([]byte("not an image"))})
	req := httptest.NewRequest(http.MethodPost, "/v1/media/upload", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "test-secret-api-key-at-least-24-bytes")
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != 415 {
		t.Fatalf("should reject nonimage: %d", resp.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/queue/start", strings.NewReader("{}"))
	req.Header.Set("X-API-Key", "test-secret-api-key-at-least-24-bytes")
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != 409 || !strings.Contains(resp.Body.String(), "rubika_login_required") {
		t.Fatalf("must reject queue start before personal login: %d %s", resp.Code, resp.Body.String())
	}
}
