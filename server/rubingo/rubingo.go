package rubingo

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"math"
	"math/big"
	mathrand "math/rand"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

// ═══════════════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════════════

const (
	DefaultUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"
	DefaultAPIVersion = "6"
	DefaultTimeout    = 20 * time.Second
	DefaultChunkSize  = 1048576
	DownloadChunk     = 131072
	URLCacheFile      = "rubika_urls.json"
)

var aesIV = make([]byte, 16)

// ═══════════════════════════════════════════════════════════════════════════════
//  Proxy Operation Names (for exclusion)
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// ProxyOpRefreshURL - عملیات گرفتن URL جدید از روبیکا (refreshAPIURL / fetchFreshURL)
	ProxyOpRefreshURL = "refreshURL"
	// ProxyOpGetDCs - عملیات GetDCs (گرفتن لیست سرورها)
	ProxyOpGetDCs = "getDCs"
	// ProxyOpAPI - درخواست‌های اصلی API (doRequest)
	ProxyOpAPI = "api"
	// ProxyOpUpload - آپلود فایل
	ProxyOpUpload = "upload"
	// ProxyOpDownload - دانلود فایل
	ProxyOpDownload = "download"
	// ProxyOpWebSocket - اتصال WebSocket
	ProxyOpWebSocket = "websocket"
)

// ═══════════════════════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════════════════════

var (
	ErrNotRegistered  = errors.New("NOT_REGISTERED")
	ErrNoConnection   = errors.New("client is not connected, call Connect() first")
	ErrNetworkError   = errors.New("network error")
	ErrStopHandler    = errors.New("stop handler")
	ErrCancelled      = errors.New("cancelled")
	ErrInvalidInput   = errors.New("invalid input")
	ErrFileNotFound   = errors.New("file not found")
	ErrSendPassKey    = errors.New("two-factor authentication required")
	ErrInvalidPassKey = errors.New("two-factor password is incorrect")
	ErrCodeInvalid    = errors.New("verification code is invalid")
	ErrCodeUsed       = errors.New("verification code has already been used")
	ErrCodeExpired    = errors.New("verification code has expired")
	ErrTooManyReqs    = errors.New("too many requests")
	ErrAllServersFail = errors.New("all servers failed")
)

type RequestError struct {
	Status    string
	StatusDet string
	Data      map[string]interface{}
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("RequestError: status=%s status_det=%s", e.Status, e.StatusDet)
}

func isInvalidOrNotRegistered(err error) bool {
	if err == nil {
		return false
	}
	var reqErr *RequestError
	if errors.As(err, &reqErr) {
		det := strings.ToUpper(reqErr.StatusDet)
		return det == "NOT_REGISTERED" ||
			det == "INVALID_INPUT" ||
			det == "INVALID_AUTH"
	}
	if errors.Is(err, ErrNotRegistered) {
		return true
	}
	errMsg := strings.ToUpper(err.Error())
	return strings.Contains(errMsg, "NOT_REGISTERED") ||
		strings.Contains(errMsg, "INVALID_INPUT") ||
		strings.Contains(errMsg, "INVALID_AUTH")
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Auth Status (AnalyzeResponse)
// ═══════════════════════════════════════════════════════════════════════════════

// AuthStatus holds the result of AnalyzeAuthResponse
type AuthStatus struct {
	// Status is the raw status string from Rubika (e.g. "SendPassKey", "CodeIsInvalid")
	Status string
	// HintPassKey is the masked hint for the 2FA password (e.g. "**word")
	HintPassKey string
	// HasEmail indicates if the user has a recovery email for 2FA
	HasEmail bool
	// Data is the raw data map from the response
	Data map[string]interface{}
	// Err is the mapped Go error
	Err error
}

// AnalyzeAuthResponse inspects a raw Rubika response map and returns an AuthStatus.
// Returns nil if the response indicates success (status OK or no special condition).
func AnalyzeAuthResponse(response map[string]interface{}) *AuthStatus {
	// Top-level error check
	status, _ := response["status"].(string)
	statusDet, _ := response["status_det"].(string)

	if status == "ERROR_GENERIC" {
		return &AuthStatus{
			Status: statusDet,
			Err:    fmt.Errorf("generic API error: %s", statusDet),
			Data:   response,
		}
	}

	data, hasData := response["data"].(map[string]interface{})
	if !hasData {
		return nil
	}

	dataStatus, _ := data["status"].(string)
	hint, _ := data["hint_pass_key"].(string)
	hasEmail, _ := data["has_confirmed_recovery_email"].(bool)

	switch dataStatus {
	case "SendPassKey":
		return &AuthStatus{
			Status:      dataStatus,
			HintPassKey: hint,
			HasEmail:    hasEmail,
			Data:        data,
			Err:         ErrSendPassKey,
		}
	case "InvalidPassKey":
		return &AuthStatus{
			Status:      dataStatus,
			HintPassKey: hint,
			HasEmail:    hasEmail,
			Data:        data,
			Err:         ErrInvalidPassKey,
		}
	case "CodeIsInvalid":
		return &AuthStatus{
			Status: dataStatus,
			Data:   data,
			Err:    ErrCodeInvalid,
		}
	case "CodeIsExpired":
		return &AuthStatus{
			Status: dataStatus,
			Data:   data,
			Err:    ErrCodeExpired,
		}
	case "CodeIsUsed":
		return &AuthStatus{
			Status: dataStatus,
			Data:   data,
			Err:    ErrCodeUsed,
		}
	case "TooManyRequests":
		return &AuthStatus{
			Status: dataStatus,
			Data:   data,
			Err:    ErrTooManyReqs,
		}
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
//  URL Cache
// ═══════════════════════════════════════════════════════════════════════════════

type URLCache struct {
	URL       string `json:"url"`
	WSSURL    string `json:"wss_url"`
	UpdatedAt string `json:"updated_at"`
}

// loadCachedURL reads a single URL from the JSON cache file.
func loadCachedURL(cacheFile string) (string, string, error) {
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return "", "", fmt.Errorf("cache file not found: %w", err)
	}
	var cache URLCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return "", "", fmt.Errorf("failed to parse cache: %w", err)
	}
	if cache.URL == "" {
		return "", "", errors.New("cache is empty")
	}
	return cache.URL, cache.WSSURL, nil
}

// saveCachedURL saves a single URL to the JSON cache file.
func saveCachedURL(cacheFile, apiURL, wssURL string) error {
	cache := URLCache{
		URL:       apiURL,
		WSSURL:    wssURL,
		UpdatedAt: time.Now().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	tmpFile := cacheFile + ".tmp." + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpFile, cacheFile)
}

// fetchFreshURL retrieves the list of Rubika API URLs from the DC endpoint,
// picks one at random, saves it to the cache file, and returns it.
func fetchFreshURL(cacheFile string, httpClient *http.Client) (string, string, error) {
	log.Println("[rubingo] Fetching fresh URLs from Rubika DC endpoint...")

	dcURL := "https://getdcmess.iranlms.ir/"
	payload := map[string]interface{}{
		"api_version": "4",
		"client": map[string]interface{}{
			"app_name":    "Main",
			"app_version": "2.4.6",
			"platform":    "PWA",
			"package":     "m.rubika.ir",
			"lang_code":   "fa",
		},
		"method": "getDCs",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	resp, err := httpClient.Post(dcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("getDCs request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", "", err
	}

	data, _ := result["data"].(map[string]interface{})
	if data == nil {
		return "", "", errors.New("getDCs: missing data field")
	}

	// ═══════════════════════════════════════════════════════
	// گرفتن API URLs
	// ═══════════════════════════════════════════════════════
	var allURLs []string

	if arr, ok := data["default_api_urls"].([]interface{}); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok && s != "" {
				allURLs = append(allURLs, ensureTrailingSlash(s))
			}
		}
	}

	if len(allURLs) == 0 {
		if apiMap, ok := data["API"].(map[string]interface{}); ok {
			for _, v := range apiMap {
				if s, ok := v.(string); ok && s != "" {
					allURLs = append(allURLs, ensureTrailingSlash(s))
				}
			}
		}
	}

	if len(allURLs) == 0 {
		return "", "", errors.New("getDCs: no API URLs found in response")
	}

	chosen := allURLs[mathrand.Intn(len(allURLs))]

	// ═══════════════════════════════════════════════════════
	// گرفتن WSS URL
	// ═══════════════════════════════════════════════════════
	wssURL := ""
	socketList, _ := data["socket"].(map[string]interface{})
	if defaultSocket, ok := data["default_socket"]; ok && socketList != nil {
		ds := fmt.Sprintf("%v", defaultSocket)
		if wss, ok := socketList[ds]; ok {
			wssURL = fmt.Sprintf("%v", wss)
		}
	}

	log.Printf("[rubingo] Got %d URLs, chose: %s, WSS: %s", len(allURLs), chosen, wssURL)

	// ═══════════════════════════════════════════════════════
	// ذخیره هر دو در فایل JSON
	// ═══════════════════════════════════════════════════════
	if err := saveCachedURL(cacheFile, chosen, wssURL); err != nil {
		log.Printf("[rubingo] Warning: failed to save URL cache: %v", err)
	}

	return chosen, wssURL, nil
}

func ensureTrailingSlash(s string) string {
	if s == "" || strings.HasSuffix(s, "/") {
		return s
	}
	return s + "/"
}

// ═══════════════════════════════════════════════════════════════════════════════
//  URL Manager (مدیریت مشترک URL برای همه client ها)
// ═══════════════════════════════════════════════════════════════════════════════

var globalURLManager = &URLManager{}

type URLManager struct {
	mu        sync.RWMutex
	apiURL    string
	wssURL    string
	refreshMu sync.Mutex
}

func (m *URLManager) GetURLs(cacheFile string, httpClient *http.Client) (string, string, error) {
	m.mu.RLock()
	if m.apiURL != "" {
		apiURL, wssURL := m.apiURL, m.wssURL
		m.mu.RUnlock()
		return apiURL, wssURL, nil
	}
	m.mu.RUnlock()

	return m.refresh(cacheFile, httpClient)
}

func (m *URLManager) refresh(cacheFile string, httpClient *http.Client) (string, string, error) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	m.mu.RLock()
	if m.apiURL != "" {
		apiURL, wssURL := m.apiURL, m.wssURL
		m.mu.RUnlock()
		return apiURL, wssURL, nil
	}
	m.mu.RUnlock()

	apiURL, wssURL, err := loadCachedURL(cacheFile)
	if err == nil && apiURL != "" {
		m.mu.Lock()
		m.apiURL = apiURL
		m.wssURL = wssURL
		m.mu.Unlock()
		return apiURL, wssURL, nil
	}

	apiURL, wssURL, err = fetchFreshURL(cacheFile, httpClient)
	if err != nil {
		return "", "", err
	}

	m.mu.Lock()
	m.apiURL = apiURL
	m.wssURL = wssURL
	m.mu.Unlock()

	return apiURL, wssURL, nil
}

func (m *URLManager) ForceRefresh(oldURL string, cacheFile string, httpClient *http.Client) (string, string, error) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	m.mu.RLock()
	currentURL := m.apiURL
	currentWSS := m.wssURL
	m.mu.RUnlock()

	if currentURL != oldURL && currentURL != "" {
		return currentURL, currentWSS, nil
	}

	apiURL, wssURL, err := fetchFreshURL(cacheFile, httpClient)
	if err != nil {
		return "", "", err
	}

	m.mu.Lock()
	m.apiURL = apiURL
	m.wssURL = wssURL
	m.mu.Unlock()

	return apiURL, wssURL, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SendCode Result
// ═══════════════════════════════════════════════════════════════════════════════

// SendCodeResult holds the result of SendCodeExt, exposing internal fields
// needed for custom session/login flows.
type SendCodeResult struct {
	// PhoneCodeHash must be passed to VerifyCodeExt / SignInExt later.
	PhoneCodeHash string
	// TmpSession is the temporary session key used for this login flow.
	TmpSession string
	// Status is the top-level data status from Rubika (e.g. "OK", "SendPassKey").
	Status string
	// AuthStatus is non-nil when 2FA or other special conditions are detected.
	AuthStatus *AuthStatus
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SignIn Result
// ═══════════════════════════════════════════════════════════════════════════════

// SignInResult holds all data returned after a successful sign-in.
// Use this to store session info in your own database.
type SignInResult struct {
	// Auth is the decrypted authentication token.
	Auth string
	// UserGUID is the user's unique identifier on Rubika.
	UserGUID string
	// PhoneNumber is the user's phone number.
	PhoneNumber string
	// FirstName is the user's first name (if available).
	FirstName string
	// LastName is the user's last name (if available).
	LastName string
	// Username is the user's @username (if set).
	Username string
	// PrivateKey is the RSA private key used for this login (PEM format).
	PrivateKey string
	// RawUser is the full user object from Rubika for any extra fields.
	RawUser map[string]interface{}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Session
// ═══════════════════════════════════════════════════════════════════════════════

// SessionMode controls how the client handles session storage.
type SessionMode int

const (
	// SessionModeFile saves session data to a SQLite file (default behavior).
	SessionModeFile SessionMode = iota
	// SessionModeCallback does NOT save to a file; instead calls OnSessionSaved
	// with the session data so the caller can store it however they like.
	SessionModeCallback
)

// SessionData contains all information needed to restore a session.
type SessionData struct {
	Auth        string
	GUID        string
	UserAgent   string
	PhoneNumber string
	PrivateKey  string
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Media Helpers
// ═══════════════════════════════════════════════════════════════════════════════

type ResultMedia struct {
	Seconds int
	Width   int
	Height  int
	Image   []byte
}

func (r *ResultMedia) ToBase64() string {
	if r.Image == nil || len(r.Image) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(r.Image)
}

func (r *ResultMedia) HasImage() bool {
	return r.Image != nil && len(r.Image) > 0
}

type MediaThumbnail struct{}

func NewMediaThumbnail() *MediaThumbnail { return &MediaThumbnail{} }

func (m *MediaThumbnail) FromImage(imageBytes []byte) *ResultMedia {
	result := &ResultMedia{Width: 200, Height: 200}
	reader := bytes.NewReader(imageBytes)
	img, _, err := image.DecodeConfig(reader)
	if err == nil {
		result.Width = img.Width
		result.Height = img.Height
	}
	if len(imageBytes) < 100*1024 {
		result.Image = imageBytes
	}
	return result
}

func (m *MediaThumbnail) FromVideo(videoBytes []byte) *ResultMedia {
	result := &ResultMedia{Seconds: 1, Width: 200, Height: 200}
	if len(videoBytes) > 32 {
		result.Seconds = m.extractMP4Duration(videoBytes)
	}
	return result
}

func (m *MediaThumbnail) extractMP4Duration(data []byte) int {
	if len(data) < 100 {
		return 1
	}
	mvhdPattern := []byte("mvhd")
	idx := bytes.Index(data, mvhdPattern)
	if idx == -1 || idx+24 >= len(data) {
		return 1
	}
	return 1
}

type AudioResult struct {
	Performer string
	Duration  int
	Title     string
}

type Audio struct{}

func NewAudio() *Audio { return &Audio{} }

func (a *Audio) GetAudioInfo(audioBytes []byte) *AudioResult {
	result := &AudioResult{Performer: "Unknown", Duration: 0, Title: ""}
	if len(audioBytes) < 128 {
		return result
	}
	if string(audioBytes[len(audioBytes)-128:len(audioBytes)-125]) == "TAG" {
		tagData := audioBytes[len(audioBytes)-128:]
		result.Title = strings.TrimSpace(string(bytes.TrimRight(tagData[3:33], "\x00")))
		result.Performer = strings.TrimSpace(string(bytes.TrimRight(tagData[33:63], "\x00")))
	}
	if len(audioBytes) > 10 && string(audioBytes[0:3]) == "ID3" {
		result = a.parseID3v2(audioBytes)
	}
	estimatedDuration := len(audioBytes) / 16000
	if estimatedDuration > 0 {
		result.Duration = estimatedDuration
	}
	return result
}

func (a *Audio) parseID3v2(data []byte) *AudioResult {
	result := &AudioResult{Performer: "Unknown", Duration: 0}
	if len(data) < 10 || string(data[0:3]) != "ID3" {
		return result
	}
	size := int(data[6])<<21 | int(data[7])<<14 | int(data[8])<<7 | int(data[9])
	if size > len(data)-10 {
		size = len(data) - 10
	}
	offset := 10
	for offset < size+10-10 {
		if offset+10 > len(data) {
			break
		}
		frameID := string(data[offset : offset+4])
		frameSize := int(binary.BigEndian.Uint32(data[offset+4 : offset+8]))
		if frameSize <= 0 || offset+10+frameSize > len(data) {
			break
		}
		frameData := data[offset+10 : offset+10+frameSize]
		switch frameID {
		case "TPE1", "TPE2":
			if len(frameData) > 1 {
				result.Performer = strings.TrimSpace(string(bytes.TrimRight(frameData[1:], "\x00")))
			}
		case "TIT2":
			if len(frameData) > 1 {
				result.Title = strings.TrimSpace(string(bytes.TrimRight(frameData[1:], "\x00")))
			}
		}
		offset += 10 + frameSize
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HTML to Markdown
// ═══════════════════════════════════════════════════════════════════════════════

type HTMLConverter struct{}

func NewHTMLConverter() *HTMLConverter { return &HTMLConverter{} }

func (h *HTMLConverter) ToMarkdown(html string) string {
	result := html
	replacements := map[string]string{
		"<b>": "**", "</b>": "**", "<strong>": "**", "</strong>": "**",
		"<i>": "__", "</i>": "__", "<em>": "__", "</em>": "__",
		"<u>": "--", "</u>": "--",
		"<s>": "~~", "</s>": "~~", "<strike>": "~~", "</strike>": "~~", "<del>": "~~", "</del>": "~~",
		"<code>": "`", "</code>": "`",
		"<br>": "\n", "<br/>": "\n", "<br />": "\n",
		"&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": "\"", "&nbsp;": " ",
	}
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}
	preRE := regexp.MustCompile(`<pre(?:\s+[^>]*)?>([^<]*)</pre>`)
	result = preRE.ReplaceAllString(result, "```$1```")
	linkRE := regexp.MustCompile(`<a\s+href=["']([^"']+)["'][^>]*>([^<]*)</a>`)
	result = linkRE.ReplaceAllString(result, "[$2]($1)")
	spoilerRE := regexp.MustCompile(`<spoiler>([^<]*)</spoiler>`)
	result = spoilerRE.ReplaceAllString(result, "||$1||")
	tagRE := regexp.MustCompile(`<[^>]+>`)
	result = tagRE.ReplaceAllString(result, "")
	return strings.TrimSpace(result)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Markdown Parser
// ═══════════════════════════════════════════════════════════════════════════════

var markdownRE = regexp.MustCompile(
	`(?m)(?:^(?:> ?[^\n]*\n?)+)` + "|" +
		"```([\\s\\S]*?)```" + "|" +
		`\*\*([^\n*]+?)\*\*` + "|" +
		"`([^\n`]+?)`" + "|" +
		`__([^\n_]+?)__` + "|" +
		`--([^\n-]+?)--` + "|" +
		`~~([^\n~]+?)~~` + "|" +
		`\|\|([^\n|]+?)\|\|` + "|" +
		`\[([^\]]+?)\]\((\S+)\)`,
)

type MetaDataPart struct {
	Type                  string                 `json:"type"`
	FromIndex             int                    `json:"from_index"`
	Length                int                    `json:"length"`
	Language              string                 `json:"language,omitempty"`
	LinkURL               string                 `json:"link_url,omitempty"`
	Link                  map[string]interface{} `json:"link,omitempty"`
	MentionTextObjectGUID string                 `json:"mention_text_object_guid,omitempty"`
	MentionTextUserID     string                 `json:"mention_text_user_id,omitempty"`
	MentionTextObjectType string                 `json:"mention_text_object_type,omitempty"`
}

type Metadata struct {
	MetaDataParts []MetaDataPart `json:"meta_data_parts"`
}

type MetadataResult struct {
	Text     string    `json:"text"`
	Metadata *Metadata `json:"metadata,omitempty"`
}

var mentionPrefixTypes = map[byte]string{
	'u': "User", 'g': "Group", 'c': "Channel", 'b': "Bot",
}

func utf16Len(s string) int {
	count := 0
	for _, r := range s {
		if r > 0xFFFF {
			count += 2
		} else {
			count++
		}
	}
	return count
}

func buildUTF16PrefixLengths(text string) []int {
	runes := []rune(text)
	prefixLengths := make([]int, len(runes)+1)
	total := 0
	for i, r := range runes {
		if r > 0xFFFF {
			total += 2
		} else {
			total++
		}
		prefixLengths[i+1] = total
	}
	return prefixLengths
}

type MarkdownParser struct {
	htmlConverter *HTMLConverter
}

func NewMarkdownParser() *MarkdownParser {
	return &MarkdownParser{htmlConverter: NewHTMLConverter()}
}

func (mp *MarkdownParser) ToMarkdown(html string) string {
	return mp.htmlConverter.ToMarkdown(html)
}

func (mp *MarkdownParser) ToMetadata(text string) MetadataResult {
	metaDataParts := []MetaDataPart{}
	currentText := text
	offset := 0
	charOffset := 0
	utf16Prefix := buildUTF16PrefixLengths(text)

	matches := markdownRE.FindAllStringIndex(text, -1)
	submatches := markdownRE.FindAllStringSubmatch(text, -1)
	submatchIndices := markdownRE.FindAllStringSubmatchIndex(text, -1)

	for mi, match := range matches {
		start := match[0]
		end := match[1]
		group := text[start:end]
		sub := submatches[mi]
		subIdx := submatchIndices[mi]

		runeStart := len([]rune(text[:start]))
		runeEnd := len([]rune(text[:end]))

		adjustedStart := utf16Prefix[runeStart] - offset
		adjustedCharStart := runeStart - charOffset

		var mdType string
		var groupIdx int
		var content string
		var contentLength int
		var charContentLength int
		found := false

		if strings.HasPrefix(group, "> ") || (strings.HasPrefix(group, ">") && !strings.HasPrefix(group, ">>")) {
			mdType = "Quote"
			lines := strings.Split(group, "\n")
			var contentLines []string
			for _, line := range lines {
				if strings.HasPrefix(line, "> ") {
					contentLines = append(contentLines, line[2:])
				} else if strings.HasPrefix(line, ">") {
					contentLines = append(contentLines, line[1:])
				} else {
					contentLines = append(contentLines, line)
				}
			}
			content = strings.Join(contentLines, "\n")
			inner := mp.ToMetadata(content)
			content = inner.Text
			contentLength = utf16Len(content)
			charContentLength = len([]rune(content))
			if inner.Metadata != nil {
				for _, part := range inner.Metadata.MetaDataParts {
					part.FromIndex += adjustedStart
					metaDataParts = append(metaDataParts, part)
				}
			}
			found = true
		} else if strings.HasPrefix(group, "```") {
			mdType = "Pre"
			groupIdx = 1
			found = true
		} else if strings.HasPrefix(group, "**") {
			mdType = "Bold"
			groupIdx = 2
			found = true
		} else if strings.HasPrefix(group, "`") {
			mdType = "Mono"
			groupIdx = 3
			found = true
		} else if strings.HasPrefix(group, "__") {
			mdType = "Italic"
			groupIdx = 4
			found = true
		} else if strings.HasPrefix(group, "--") {
			mdType = "Underline"
			groupIdx = 5
			found = true
		} else if strings.HasPrefix(group, "~~") {
			mdType = "Strike"
			groupIdx = 6
			found = true
		} else if strings.HasPrefix(group, "||") {
			mdType = "Spoiler"
			groupIdx = 7
			found = true
		} else if strings.HasPrefix(group, "[") {
			mdType = "Link"
			groupIdx = 8
			found = true
		}

		if !found {
			continue
		}

		if mdType != "Quote" {
			if groupIdx > 0 && groupIdx < len(sub) && sub[groupIdx] != "" {
				content = sub[groupIdx]
				gStart := subIdx[groupIdx*2]
				gEnd := subIdx[groupIdx*2+1]
				if gStart >= 0 && gEnd >= 0 {
					runeGStart := len([]rune(text[:gStart]))
					runeGEnd := len([]rune(text[:gEnd]))
					contentLength = utf16Prefix[runeGEnd] - utf16Prefix[runeGStart]
					charContentLength = runeGEnd - runeGStart
				}
				if mdType != "Pre" && mdType != "Link" {
					inner := mp.ToMetadata(content)
					content = inner.Text
					contentLength = utf16Len(content)
					charContentLength = len([]rune(content))
					if inner.Metadata != nil {
						for _, part := range inner.Metadata.MetaDataParts {
							part.FromIndex += adjustedStart
							metaDataParts = append(metaDataParts, part)
						}
					}
				}
			} else {
				content = ""
				contentLength = 0
				charContentLength = 0
			}
		}

		part := MetaDataPart{Type: mdType, FromIndex: adjustedStart, Length: contentLength}

		if mdType == "Pre" {
			lines := strings.SplitN(content, "\n", 2)
			part.Language = strings.TrimSpace(lines[0])
		} else if mdType == "Link" {
			linkURL := ""
			if len(sub) > 9 {
				linkURL = sub[9]
			}
			if len(linkURL) > 0 {
				mentionType, ok := mentionPrefixTypes[linkURL[0]]
				if !ok {
					part.LinkURL = linkURL
					part.Link = map[string]interface{}{
						"type":           "hyperlink",
						"hyperlink_data": map[string]string{"url": linkURL},
					}
				} else {
					part.Type = "MentionText"
					part.MentionTextObjectGUID = linkURL
					part.MentionTextUserID = linkURL
					part.MentionTextObjectType = mentionType
				}
			}
		}

		metaDataParts = append(metaDataParts, part)

		markupLength := utf16Prefix[runeEnd] - utf16Prefix[runeStart]
		charMarkupLength := runeEnd - runeStart

		runeCurrentText := []rune(currentText)
		newText := make([]rune, 0, len(runeCurrentText))
		newText = append(newText, runeCurrentText[:adjustedCharStart]...)
		newText = append(newText, []rune(content)...)
		restStart := runeEnd - charOffset
		if restStart < len(runeCurrentText) {
			newText = append(newText, runeCurrentText[restStart:]...)
		}
		currentText = string(newText)

		offset += markupLength - contentLength
		charOffset += charMarkupLength - charContentLength
	}

	result := MetadataResult{Text: strings.TrimSpace(currentText)}
	if len(metaDataParts) > 0 {
		result.Metadata = &Metadata{MetaDataParts: metaDataParts}
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Crypto
// ═══════════════════════════════════════════════════════════════════════════════

type CryptoHelper struct{}

func NewCrypto() *CryptoHelper { return &CryptoHelper{} }

func (c *CryptoHelper) DecodeAuth(auth string) string {
	lowerTo := make([]byte, 26)
	for i := 0; i < 26; i++ {
		lowerTo[i] = byte(((32 - i) % 26) + 97)
	}
	upperTo := make([]byte, 26)
	for i := 0; i < 26; i++ {
		upperTo[i] = byte(((29 - i) % 26) + 65)
	}
	digitTo := make([]byte, 10)
	for i := 0; i < 10; i++ {
		digitTo[i] = byte(((13 - i) % 10) + 48)
	}
	var result strings.Builder
	for _, ch := range auth {
		if ch >= 'a' && ch <= 'z' {
			result.WriteByte(lowerTo[ch-'a'])
		} else if ch >= 'A' && ch <= 'Z' {
			result.WriteByte(upperTo[ch-'A'])
		} else if ch >= '0' && ch <= '9' {
			result.WriteByte(digitTo[ch-'0'])
		} else {
			result.WriteRune(ch)
		}
	}
	return result.String()
}

func (c *CryptoHelper) Passphrase(auth string) string {
	if len(auth) != 32 {
		panic("auth length should be 32 digits")
	}
	chunks := make([]string, 4)
	for i := 0; i < 4; i++ {
		chunks[i] = auth[i*8 : (i+1)*8]
	}
	combined := chunks[2] + chunks[0] + chunks[3] + chunks[1]
	var result strings.Builder
	for _, ch := range combined {
		result.WriteByte(byte(((int(ch) - 97 + 9) % 26) + 97))
	}
	return result.String()
}

func (c *CryptoHelper) Secret(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[n.Int64()]
	}
	return string(b)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

func (c *CryptoHelper) Encrypt(data interface{}, key string) (string, error) {
	var plaintext []byte
	switch v := data.(type) {
	case string:
		plaintext = []byte(v)
	default:
		j, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		plaintext = j
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, aesIV)
	mode.CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *CryptoHelper) Decrypt(data string, key string) (map[string]interface{}, error) {
	decoded, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("base64 decode error: %w", err)
		}
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	if len(decoded)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, aesIV)
	mode.CryptBlocks(decoded, decoded)
	unpadded, err := pkcs7Unpad(decoded)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(unpadded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *CryptoHelper) Sign(privateKey *rsa.PrivateKey, data string) (string, error) {
	hash := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (c *CryptoHelper) CreateKeys() (publicKeyEncoded string, privateKeyPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return "", "", err
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1})
	pubEncoded := base64.StdEncoding.EncodeToString(pubPEM)
	publicKeyEncoded = c.DecodeAuth(pubEncoded)

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	privateKeyPEM = string(privPEM)
	return publicKeyEncoded, privateKeyPEM, nil
}

func (c *CryptoHelper) DecryptRSAOAEP(privateKeyPEM string, data string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", errors.New("failed to parse PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	plaintext, err1 := rsa.DecryptPKCS1v15(rand.Reader, key, decoded)
	if err1 == nil {
		return string(plaintext), nil
	}
	plaintext, err2 := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, decoded, nil)
	if err2 == nil {
		return string(plaintext), nil
	}
	plaintext, err3 := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, decoded, nil)
	if err3 == nil {
		return string(plaintext), nil
	}
	return "", fmt.Errorf("all decryption methods failed: pkcs1v15=%v, oaep_sha1=%v, oaep_sha256=%v", err1, err2, err3)
}

func parsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	if !strings.HasPrefix(privateKeyPEM, "-----BEGIN RSA PRIVATE KEY-----") {
		privateKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\n" + privateKeyPEM
	}
	if !strings.HasSuffix(strings.TrimSpace(privateKeyPEM), "-----END RSA PRIVATE KEY-----") {
		privateKeyPEM = strings.TrimSpace(privateKeyPEM) + "\n-----END RSA PRIVATE KEY-----"
	}
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Update
// ═══════════════════════════════════════════════════════════════════════════════

type Update struct {
	Data   map[string]interface{}
	Client *RubClient
}

func NewUpdate(data map[string]interface{}) *Update {
	u := &Update{Data: data}
	if c, ok := data["client"]; ok {
		if client, ok := c.(*RubClient); ok {
			u.Client = client
		}
	}
	return u
}

func (u *Update) String() string {
	j, _ := json.MarshalIndent(u.Data, "", "  ")
	return string(j)
}

func (u *Update) Get(key string) interface{} {
	return u.FindKeys([]string{key}, u.Data)
}

func (u *Update) GetString(key string) string {
	v := u.Get(key)
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func (u *Update) GetFloat64(key string) float64 {
	v := u.Get(key)
	if v == nil {
		return 0
	}
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func (u *Update) GetInt(key string) int {
	v := u.Get(key)
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	case string:
		i, _ := strconv.Atoi(val)
		return i
	}
	return 0
}

func (u *Update) GetBool(key string) bool {
	v := u.Get(key)
	if v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func (u *Update) GetMap(key string) map[string]interface{} {
	v := u.Get(key)
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func (u *Update) GetUpdate(key string) *Update {
	m := u.GetMap(key)
	if m == nil {
		return nil
	}
	return NewUpdate(m)
}

func (u *Update) GetSlice(key string) []interface{} {
	v := u.Get(key)
	if v == nil {
		return nil
	}
	if s, ok := v.([]interface{}); ok {
		return s
	}
	return nil
}

func (u *Update) FindKeys(keys []string, data interface{}) interface{} {
	if data == nil {
		data = u.Data
	}
	switch d := data.(type) {
	case map[string]interface{}:
		for _, key := range keys {
			if val, ok := d[key]; ok {
				return val
			}
		}
		for _, val := range d {
			result := u.FindKeys(keys, val)
			if result != nil {
				return result
			}
		}
	case []interface{}:
		for _, val := range d {
			result := u.FindKeys(keys, val)
			if result != nil {
				return result
			}
		}
	}
	return nil
}

func (u *Update) ObjectGUID() string {
	v := u.FindKeys([]string{"group_guid", "object_guid", "channel_guid"}, u.Data)
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func (u *Update) MessageID() string {
	v := u.FindKeys([]string{"message_id", "pinned_message_id"}, u.Data)
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func (u *Update) AuthorGUID() string {
	msg := u.GetMap("message")
	if msg == nil {
		return ""
	}
	if v, ok := msg["author_object_guid"]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func (u *Update) Text() string {
	msg := u.GetMap("message")
	if msg == nil {
		return ""
	}
	if v, ok := msg["text"]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func (u *Update) Type() string {
	v := u.FindKeys([]string{"type", "author_type"}, u.Data)
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func (u *Update) ReplyMessageID() string {
	msg := u.GetMap("message")
	if msg == nil {
		return ""
	}
	if v, ok := msg["reply_to_message_id"]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func (u *Update) Title() string   { return u.GetString("title") }
func (u *Update) Command() string { return u.GetString("command") }
func (u *Update) Status() string  { return u.GetString("status") }
func (u *Update) Action() bool    { _, ok := u.Data["action"]; return ok }
func (u *Update) IsGroup() bool   { return u.Type() == "Group" }
func (u *Update) IsChannel() bool { return u.Type() == "Channel" }
func (u *Update) IsPrivate() bool { return u.Type() == "User" }

func (u *Update) IsMe() bool {
	if u.Client == nil {
		return false
	}
	return u.AuthorGUID() == u.Client.GUID
}

func (u *Update) IsEdited() bool {
	msg := u.GetMap("message")
	if msg == nil {
		return false
	}
	_, ok := msg["is_edited"]
	return ok
}

func (u *Update) IsForward() bool {
	msg := u.GetMap("message")
	if msg == nil {
		return false
	}
	_, ok := msg["forwarded_from"]
	return ok
}

func (u *Update) ForwardTypeFrom() string {
	msg := u.GetMap("message")
	if msg == nil {
		return ""
	}
	if ff, ok := msg["forwarded_from"].(map[string]interface{}); ok {
		if tf, ok := ff["type_from"].(string); ok {
			return tf
		}
	}
	return ""
}

func (u *Update) IsEvent() bool {
	msg := u.GetMap("message")
	if msg == nil {
		return false
	}
	if t, ok := msg["type"].(string); ok {
		return t == "Event"
	}
	return false
}

func (u *Update) EventData() *Update {
	if !u.IsEvent() {
		return nil
	}
	msg := u.GetMap("message")
	if msg == nil {
		return nil
	}
	if ed, ok := msg["event_data"].(map[string]interface{}); ok {
		return NewUpdate(ed)
	}
	return nil
}

func (u *Update) IsText() bool {
	msg := u.GetMap("message")
	if msg == nil {
		return false
	}
	if t, ok := msg["type"].(string); ok {
		return t == "Text"
	}
	return false
}

func (u *Update) IsFileInline() bool {
	msg := u.GetMap("message")
	if msg == nil {
		return false
	}
	if t, ok := msg["type"].(string); ok {
		return t == "FileInline" || t == "FileInlineCaption"
	}
	return false
}

func (u *Update) FileInline() *Update {
	fi := u.GetMap("file_inline")
	if fi == nil {
		return nil
	}
	up := NewUpdate(fi)
	up.Client = u.Client
	return up
}

func (u *Update) FileType() string {
	fi := u.FileInline()
	if fi == nil {
		return ""
	}
	return fi.GetString("type")
}

func (u *Update) IsMusic() bool    { return u.FileType() == "Music" }
func (u *Update) IsFile() bool     { return u.FileType() == "File" }
func (u *Update) IsPhoto() bool    { return u.FileType() == "Image" }
func (u *Update) IsVideo() bool    { return u.FileType() == "Video" }
func (u *Update) IsVoice() bool    { return u.FileType() == "Voice" }
func (u *Update) IsGif() bool      { return u.FileType() == "Gif" }
func (u *Update) IsContact() bool  { return u.FileType() == "Contact" }
func (u *Update) IsLocation() bool { return u.FileType() == "Location" }
func (u *Update) IsPoll() bool     { return u.FileType() == "Poll" }

func (u *Update) Sticker() *Update {
	s := u.GetMap("sticker")
	if s == nil {
		return nil
	}
	return NewUpdate(s)
}

func (u *Update) IsSticker() bool { return u.Sticker() != nil }

func (u *Update) GUIDType(objectGUID string) string {
	if objectGUID == "" {
		objectGUID = u.ObjectGUID()
	}
	if strings.HasPrefix(objectGUID, "c0") {
		return "Channel"
	} else if strings.HasPrefix(objectGUID, "g0") {
		return "Group"
	}
	return "User"
}

func (u *Update) ToDict() map[string]interface{} { return u.Data }

// ─── Update action methods ────────────────────────────────────────────────────

func (u *Update) Reply(text string, opts ...SendMessageOptions) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	options := SendMessageOptions{
		ObjectGUID:       u.ObjectGUID(),
		Text:             text,
		ReplyToMessageID: u.MessageID(),
	}
	if len(opts) > 0 {
		opt := opts[0]
		if opt.FileInline != nil {
			options.FileInline = opt.FileInline
		}
		if opt.Type != "" {
			options.Type = opt.Type
		}
		if opt.AutoDelete > 0 {
			options.AutoDelete = opt.AutoDelete
		}
		if opt.ParseMode != "" {
			options.ParseMode = opt.ParseMode
		}
	}
	return u.Client.SendMessage(options)
}

func (u *Update) ReplyPhoto(photo interface{}, caption string) (*Update, error) {
	return u.Client.SendMessage(SendMessageOptions{ObjectGUID: u.ObjectGUID(), Text: caption, ReplyToMessageID: u.MessageID(), FileInline: photo, Type: "Image"})
}
func (u *Update) ReplyVideo(video interface{}, caption string) (*Update, error) {
	return u.Client.SendMessage(SendMessageOptions{ObjectGUID: u.ObjectGUID(), Text: caption, ReplyToMessageID: u.MessageID(), FileInline: video, Type: "Video"})
}
func (u *Update) ReplyDocument(doc interface{}, caption string) (*Update, error) {
	return u.Client.SendMessage(SendMessageOptions{ObjectGUID: u.ObjectGUID(), Text: caption, ReplyToMessageID: u.MessageID(), FileInline: doc, Type: "File"})
}
func (u *Update) ReplyMusic(music interface{}, caption string) (*Update, error) {
	return u.Client.SendMessage(SendMessageOptions{ObjectGUID: u.ObjectGUID(), Text: caption, ReplyToMessageID: u.MessageID(), FileInline: music, Type: "Music"})
}
func (u *Update) ReplyVoice(voice interface{}, caption string) (*Update, error) {
	return u.Client.SendMessage(SendMessageOptions{ObjectGUID: u.ObjectGUID(), Text: caption, ReplyToMessageID: u.MessageID(), FileInline: voice, Type: "Voice"})
}
func (u *Update) ReplyGif(gif interface{}, caption string) (*Update, error) {
	return u.Client.SendMessage(SendMessageOptions{ObjectGUID: u.ObjectGUID(), Text: caption, ReplyToMessageID: u.MessageID(), FileInline: gif, Type: "Gif"})
}
func (u *Update) ReplyVideoMessage(video interface{}, caption string) (*Update, error) {
	return u.Client.SendMessage(SendMessageOptions{ObjectGUID: u.ObjectGUID(), Text: caption, ReplyToMessageID: u.MessageID(), FileInline: video, Type: "VideoMessage"})
}

func (u *Update) Forward(toObjectGUID string) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.ForwardMessages(u.ObjectGUID(), toObjectGUID, []string{u.MessageID()})
}

func (u *Update) Forwards(toObjectGUID string, messageIDs []string) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	if messageIDs == nil {
		messageIDs = []string{u.MessageID()}
	}
	return u.Client.ForwardMessages(u.ObjectGUID(), toObjectGUID, messageIDs)
}

func (u *Update) Edit(text string) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.EditMessage(u.ObjectGUID(), u.MessageID(), text)
}

func (u *Update) Delete() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.DeleteMessages(u.ObjectGUID(), []string{u.MessageID()})
}

func (u *Update) DeleteMessages(messageIDs []string) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	if messageIDs == nil {
		messageIDs = []string{u.MessageID()}
	}
	return u.Client.DeleteMessages(u.ObjectGUID(), messageIDs)
}

func (u *Update) Pin() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.SetPinMessage(u.ObjectGUID(), u.MessageID(), "Pin")
}

func (u *Update) Unpin() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.SetPinMessage(u.ObjectGUID(), u.MessageID(), "Unpin")
}

func (u *Update) Seen() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.SeenChats(map[string]string{u.ObjectGUID(): u.MessageID()})
}

func (u *Update) Download(saveAs string) ([]byte, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	fi := u.FileInline()
	if fi == nil {
		return nil, errors.New("no file_inline in this update")
	}
	return u.Client.DownloadFile(fi, saveAs)
}

func (u *Update) Reaction(reactionID int) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.ActionOnMessageReaction(u.ObjectGUID(), u.MessageID(), "Add", reactionID)
}

func (u *Update) RemoveReaction(reactionID int) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.ActionOnMessageReaction(u.ObjectGUID(), u.MessageID(), "Remove", reactionID)
}

func (u *Update) BanMember() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	objectGUID := u.ObjectGUID()
	userGUID := u.AuthorGUID()
	if strings.HasPrefix(objectGUID, "g0") {
		return u.Client.BanGroupMember(objectGUID, userGUID, "Set")
	} else if strings.HasPrefix(objectGUID, "c0") {
		return u.Client.BanChannelMember(objectGUID, userGUID, "Set")
	}
	return nil, errors.New("cannot ban in private chat")
}

func (u *Update) UnbanMember() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	objectGUID := u.ObjectGUID()
	userGUID := u.AuthorGUID()
	if strings.HasPrefix(objectGUID, "g0") {
		return u.Client.BanGroupMember(objectGUID, userGUID, "Unset")
	} else if strings.HasPrefix(objectGUID, "c0") {
		return u.Client.BanChannelMember(objectGUID, userGUID, "Unset")
	}
	return nil, errors.New("cannot unban in private chat")
}

func (u *Update) Block() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	userGUID := u.AuthorGUID()
	if userGUID == "" {
		userGUID = u.ObjectGUID()
	}
	return u.Client.SetBlockUser(userGUID)
}

func (u *Update) SendActivity(activity string) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	if activity == "" {
		activity = "Typing"
	}
	return u.Client.SendChatActivity(u.ObjectGUID(), activity)
}

func (u *Update) GetAuthor() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.GetInfo(u.AuthorGUID())
}

func (u *Update) GetObject() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	return u.Client.GetInfo(u.ObjectGUID())
}

func (u *Update) GetMessages(messageIDs []string) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	if messageIDs == nil {
		messageIDs = []string{u.MessageID()}
	}
	return u.Client.GetMessagesByID(u.ObjectGUID(), messageIDs)
}

func (u *Update) GetReplyMessage() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	replyID := u.ReplyMessageID()
	if replyID == "" {
		return nil, nil
	}
	result, err := u.Client.GetMessagesByID(u.ObjectGUID(), []string{replyID})
	if err != nil {
		return nil, err
	}
	messages := result.GetSlice("messages")
	if len(messages) > 0 {
		if msg, ok := messages[0].(map[string]interface{}); ok {
			return NewUpdate(msg), nil
		}
	}
	return nil, nil
}

func (u *Update) GetReplyAuthor() (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	replyMsg, err := u.GetReplyMessage()
	if err != nil || replyMsg == nil {
		return nil, err
	}
	authorGUID := replyMsg.AuthorGUID()
	if authorGUID == "" {
		return nil, nil
	}
	return u.Client.GetInfo(authorGUID)
}

func (u *Update) IsAdmin(userGUID string) (bool, error) {
	if u.Client == nil {
		return false, ErrNoConnection
	}
	if userGUID == "" {
		userGUID = u.AuthorGUID()
	}
	objectGUID := u.ObjectGUID()
	if strings.HasPrefix(objectGUID, "g0") {
		result, err := u.Client.GetGroupAdminMembers(objectGUID)
		if err != nil {
			return false, err
		}
		members := result.GetSlice("in_chat_members")
		for _, m := range members {
			if member, ok := m.(map[string]interface{}); ok {
				if guid, ok := member["member_guid"].(string); ok && guid == userGUID {
					return true, nil
				}
			}
		}
	} else if strings.HasPrefix(objectGUID, "c0") {
		result, err := u.Client.GetChannelAdminMembers(objectGUID)
		if err != nil {
			return false, err
		}
		members := result.GetSlice("in_chat_members")
		for _, m := range members {
			if member, ok := m.(map[string]interface{}); ok {
				if guid, ok := member["member_guid"].(string); ok && guid == userGUID {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (u *Update) Copy(toObjectGUID string) (*Update, error) {
	if u.Client == nil {
		return nil, ErrNoConnection
	}
	result, err := u.Client.GetMessagesByID(u.ObjectGUID(), []string{u.MessageID()})
	if err != nil {
		return nil, err
	}
	messages := result.GetSlice("messages")
	if len(messages) == 0 {
		return nil, errors.New("message not found")
	}
	msg, ok := messages[0].(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid message format")
	}
	msgUpdate := NewUpdate(msg)
	msgUpdate.Client = u.Client
	text := msgUpdate.Text()
	sticker := msgUpdate.Sticker()
	fileInline := msgUpdate.FileInline()
	if sticker != nil {
		return u.Client.SendMessage(SendMessageOptions{ObjectGUID: toObjectGUID, Sticker: sticker.Data})
	}
	if fileInline != nil {
		fileType := fileInline.GetString("type")
		if fileType != "Gif" && fileType != "Sticker" {
			data, err := u.Client.DownloadFile(fileInline, "")
			if err != nil {
				return nil, err
			}
			return u.Client.SendMessage(SendMessageOptions{ObjectGUID: toObjectGUID, Text: text, FileInline: data, Type: fileType, FileName: fileInline.GetString("file_name")})
		}
		return u.Client.SendMessage(SendMessageOptions{ObjectGUID: toObjectGUID, Text: text, FileInline: fileInline.Data, Type: fileType})
	}
	return u.Client.SendMessage(SendMessageOptions{ObjectGUID: toObjectGUID, Text: text})
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Session Types
// ═══════════════════════════════════════════════════════════════════════════════

type SQLiteSession struct {
	name string
	db   *sql.DB
}

func NewSQLiteSession(name string) (*SQLiteSession, error) {
	dbPath := name
	if !strings.HasSuffix(dbPath, ".db") && !strings.HasSuffix(dbPath, ".sqlite") {
		dbPath = name + ".session"
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS session (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			auth TEXT NOT NULL DEFAULT '',
			guid TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			phone_number TEXT NOT NULL DEFAULT '',
			private_key TEXT NOT NULL DEFAULT ''
		)
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create session table: %w", err)
	}
	return &SQLiteSession{name: name, db: db}, nil
}

type SessionInfo struct {
	ID          int64
	Auth        string
	GUID        string
	UserAgent   string
	PhoneNumber string
	PrivateKey  string
}

func (s *SQLiteSession) Information() *SessionInfo {
	row := s.db.QueryRow("SELECT id, auth, guid, user_agent, phone_number, private_key FROM session ORDER BY id DESC LIMIT 1")
	info := &SessionInfo{}
	err := row.Scan(&info.ID, &info.Auth, &info.GUID, &info.UserAgent, &info.PhoneNumber, &info.PrivateKey)
	if err != nil || info.Auth == "" {
		return nil
	}
	return info
}

func (s *SQLiteSession) Insert(auth, guid, userAgent, phoneNumber, privateKey string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM session"); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO session (auth, guid, user_agent, phone_number, private_key) VALUES (?, ?, ?, ?, ?)", auth, guid, userAgent, phoneNumber, privateKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteSession) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

type StringSession struct {
	Auth       string
	GUID       string
	UserAgent  string
	PrivateKey string
}

func NewStringSession(sessionString string) (*StringSession, error) {
	if sessionString == "" {
		return &StringSession{}, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(sessionString)
	if err != nil {
		return nil, fmt.Errorf("invalid session string: %w", err)
	}
	var data map[string]string
	if err := json.Unmarshal(decoded, &data); err != nil {
		return nil, fmt.Errorf("invalid session format: %w", err)
	}
	return &StringSession{
		Auth:       data["auth"],
		GUID:       data["guid"],
		UserAgent:  data["user_agent"],
		PrivateKey: data["private_key"],
	}, nil
}

func (s *StringSession) Encode() (string, error) {
	data := map[string]string{"auth": s.Auth, "guid": s.GUID, "user_agent": s.UserAgent, "private_key": s.PrivateKey}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonData), nil
}

func (s *StringSession) Information() *SessionInfo {
	if s.Auth == "" {
		return nil
	}
	return &SessionInfo{Auth: s.Auth, GUID: s.GUID, UserAgent: s.UserAgent, PrivateKey: s.PrivateKey}
}

func (s *StringSession) Insert(auth, guid, userAgent, phoneNumber, privateKey string) error {
	s.Auth = auth
	s.GUID = guid
	s.UserAgent = userAgent
	s.PrivateKey = privateKey
	return nil
}

func (s *StringSession) Close() error { return nil }

type Session interface {
	Information() *SessionInfo
	Insert(auth, guid, userAgent, phoneNumber, privateKey string) error
	Close() error
}

// ─── NoOpSession: does not persist anything ───────────────────────────────────

// NoOpSession is used when SessionModeCallback is set.
// It holds data in memory and fires the OnSessionSaved callback.
type NoOpSession struct {
	info *SessionInfo
}

func (s *NoOpSession) Information() *SessionInfo { return s.info }
func (s *NoOpSession) Insert(auth, guid, userAgent, phoneNumber, privateKey string) error {
	s.info = &SessionInfo{Auth: auth, GUID: guid, UserAgent: userAgent, PhoneNumber: phoneNumber, PrivateKey: privateKey}
	return nil
}
func (s *NoOpSession) Close() error { return nil }

// ═══════════════════════════════════════════════════════════════════════════════
//  Network
// ═══════════════════════════════════════════════════════════════════════════════

type Network struct {
	client       *RubClient
	maxRetries   int
	httpClient   *http.Client
	directClient *http.Client // همیشه بدون پروکسی
	headers      map[string]string
	apiURL       string
	wssURL       string
	wsConn       *websocket.Conn
	wsMu         sync.Mutex
	cryptoHelper *CryptoHelper
	cacheFile    string

	proxyURL     string
	proxyEnabled bool
	httpMu       sync.RWMutex
}

func NewNetwork(client *RubClient) *Network {
	headers := map[string]string{
		"origin":       "https://m.rubika.ir",
		"referer":      "https://m.rubika.ir/",
		"content-type": "application/json",
		"connection":   "keep-alive",
		"user-agent":   client.UserAgent,
	}

	transport := &http.Transport{
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if client.ProxyEnabled && client.Proxy != "" {
		proxyURL, err := url.Parse(client.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			log.Printf("[rubingo] Proxy enabled: %s", client.Proxy)
		} else {
			log.Printf("[rubingo] Warning: invalid proxy URL: %v", err)
		}
	}

	if client.DefaultPlatform["platform"] == "Android" {
		delete(headers, "origin")
		delete(headers, "referer")
		headers["user-agent"] = "okhttp/3.12.1"
		client.DefaultPlatform["package"] = "app.rbmain.a"
		client.DefaultPlatform["app_version"] = "3.8.2"
	}

	cacheFile := client.URLCacheFile
	if cacheFile == "" {
		cacheFile = URLCacheFile
	}

	// ═══════════════════════════════════════════════════════
	// directClient: همیشه بدون پروکسی
	// ═══════════════════════════════════════════════════════
	directTransport := &http.Transport{
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	directClient := &http.Client{
		Timeout:   client.Timeout,
		Transport: directTransport,
	}

	return &Network{
		client:       client,
		maxRetries:   client.MaxRetries,
		httpClient:   &http.Client{Timeout: client.Timeout, Transport: transport},
		directClient: directClient,
		headers:      headers,
		cryptoHelper: NewCrypto(),
		cacheFile:    cacheFile,
		proxyURL:     client.Proxy,
		proxyEnabled: client.ProxyEnabled,
	}
}

// updateProxy پروکسی را در زمان اجرا تغییر می‌دهد
func (n *Network) updateProxy(proxyURL string, enabled bool) {
	n.httpMu.Lock()
	defer n.httpMu.Unlock()

	n.proxyURL = proxyURL
	n.proxyEnabled = enabled

	transport := &http.Transport{
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if enabled && proxyURL != "" {
		parsedURL, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(parsedURL)
			log.Printf("[rubingo] Proxy updated and enabled: %s", proxyURL)
		} else {
			log.Printf("[rubingo] Warning: invalid proxy URL: %v", err)
		}
	} else {
		log.Printf("[rubingo] Proxy disabled")
	}

	n.httpClient = &http.Client{
		Timeout:   n.client.Timeout,
		Transport: transport,
	}
}

// getHTTPClient برمی‌گرداند HTTP client (thread-safe)
func (n *Network) getHTTPClient() *http.Client {
	n.httpMu.RLock()
	defer n.httpMu.RUnlock()
	return n.httpClient
}

// getClientFor برمی‌گرداند HTTP client مناسب برای عملیات مورد نظر
// اگر عملیات در لیست exclude باشد، از directClient (بدون پروکسی) استفاده می‌شود
func (n *Network) getClientFor(operation string) *http.Client {
	// اگر عملیات exclude شده باشد → همیشه بدون پروکسی
	if n.client.ProxyExclude != nil && n.client.ProxyExclude[operation] {
		return n.directClient
	}
	// در غیر این صورت از httpClient فعلی (با یا بدون پروکسی) استفاده کن
	n.httpMu.RLock()
	defer n.httpMu.RUnlock()
	return n.httpClient
}

// getAPIURL returns the cached URL or fetches a fresh one.
func (n *Network) getAPIURL() (string, error) {
	if n.apiURL != "" {
		return n.apiURL, nil
	}

	apiURL, wssURL, err := globalURLManager.GetURLs(n.cacheFile, n.getClientFor(ProxyOpRefreshURL))
	if err != nil {
		return "", err
	}
	n.apiURL = apiURL
	n.wssURL = wssURL
	return apiURL, nil
}

// refreshAPIURL ignores cache and fetches a new URL from Rubika.

func (n *Network) refreshAPIURL() (string, error) {
	log.Println("[rubingo] Refreshing API URL from Rubika...")

	apiURL, wssURL, err := globalURLManager.ForceRefresh(n.apiURL, n.cacheFile, n.getClientFor(ProxyOpRefreshURL))
	if err != nil {
		return "", err
	}
	n.apiURL = apiURL
	n.wssURL = wssURL
	return apiURL, nil
}

func (n *Network) refreshWSSURL() {
	log.Println("[rubingo] Refreshing WSS URL from Rubika...")

	apiURL, wssURL, err := globalURLManager.ForceRefresh(n.apiURL, n.cacheFile, n.getClientFor(ProxyOpRefreshURL))
	if err != nil {
		log.Printf("[rubingo] Failed to refresh WSS URL: %v", err)
		return
	}
	n.apiURL = apiURL
	n.wssURL = wssURL
}

func (n *Network) GetDCs() error {
	apiURL, wssURL, err := globalURLManager.GetURLs(n.cacheFile, n.getClientFor(ProxyOpGetDCs))
	if err != nil {
		return fmt.Errorf("failed to get URLs: %w", err)
	}
	n.apiURL = apiURL
	n.wssURL = wssURL
	return nil
}

func exponentialBackoff(attempt int) time.Duration {
	return time.Duration(math.Pow(2, float64(attempt))) * time.Second
}

func (n *Network) doRequest(data interface{}) (map[string]interface{}, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	apiURL, err := n.getAPIURL()
	if err != nil {
		return nil, err
	}

	for attempt := 0; attempt < n.maxRetries; attempt++ {
		req, err := http.NewRequest("POST", apiURL, bytes.NewReader(jsonData))
		if err != nil {
			return nil, err
		}
		for k, v := range n.headers {
			req.Header.Set(k, v)
		}

		resp, err := n.getClientFor(ProxyOpAPI).Do(req)
		if err != nil {
			log.Printf("[rubingo] Request failed (attempt %d/%d): %v — refreshing URL", attempt+1, n.maxRetries, err)
			newURL, refreshErr := n.refreshAPIURL()
			if refreshErr != nil {
				return nil, fmt.Errorf("request failed and URL refresh failed: %w", refreshErr)
			}
			apiURL = newURL
			time.Sleep(exponentialBackoff(attempt))
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}

		return result, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts", n.maxRetries)
}

type SendOpts struct {
	APIVersion string
	Auth       string
	ClientInfo map[string]string
	Input      map[string]interface{}
	Method     string
	Encrypt    bool
	TmpSession bool
	URL        string
}

func (n *Network) Send(opts SendOpts) (map[string]interface{}, error) {
	if opts.APIVersion == "" {
		opts.APIVersion = n.client.APIVersion
	}
	if opts.Auth == "" {
		opts.Auth = n.client.Auth
	}
	if opts.ClientInfo == nil {
		opts.ClientInfo = n.client.DefaultPlatform
	}
	if opts.Input == nil {
		opts.Input = make(map[string]interface{})
	}
	if opts.Method == "" {
		opts.Method = "getUserInfo"
	}

	data := map[string]interface{}{
		"api_version": opts.APIVersion,
	}

	if opts.TmpSession {
		data["tmp_session"] = opts.Auth
	} else {
		data["auth"] = n.client.DecodeAuthStr
	}

	if opts.APIVersion == "6" {
		clientMap := make(map[string]interface{})
		for k, v := range opts.ClientInfo {
			clientMap[k] = v
		}
		dataEnc := map[string]interface{}{
			"client": clientMap,
			"method": opts.Method,
			"input":  opts.Input,
		}

		if opts.Encrypt {
			encrypted, err := n.cryptoHelper.Encrypt(dataEnc, n.client.Key)
			if err != nil {
				return nil, fmt.Errorf("encryption error: %w", err)
			}
			data["data_enc"] = encrypted

			if !opts.TmpSession && n.client.ImportKey != nil {
				sign, err := n.cryptoHelper.Sign(n.client.ImportKey, encrypted)
				if err != nil {
					return nil, fmt.Errorf("sign error: %w", err)
				}
				data["sign"] = sign
			}
		}
	}

	return n.doRequest(data)
}

func (n *Network) Close() error {
	n.wsMu.Lock()
	defer n.wsMu.Unlock()
	if n.wsConn != nil {
		err := n.wsConn.Close()
		n.wsConn = nil
		return err
	}
	return nil
}

func (n *Network) GetUpdates(stopCh <-chan struct{}) {
	go n.keepSocket(stopCh)

	dialFails := 0

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		if n.wssURL == "" {
			time.Sleep(2 * time.Second)
			continue
		}

		dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}

		if n.proxyEnabled && n.proxyURL != "" {
			if n.client.ProxyExclude == nil || !n.client.ProxyExclude[ProxyOpWebSocket] {
				if proxyURL, err := url.Parse(n.proxyURL); err == nil {
					dialer.Proxy = http.ProxyURL(proxyURL)
				}
			}
		}

		conn, _, err := dialer.Dial(n.wssURL, nil)
		if err != nil {
			dialFails++
			log.Printf("[rubingo] WSS Dial failed (%d/3): %v", dialFails, err)
			if dialFails >= 3 {
				n.refreshWSSURL()
				dialFails = 0
			}
			time.Sleep(3 * time.Second)
			continue
		}

		dialFails = 0

		n.wsMu.Lock()
		n.wsConn = conn
		n.wsMu.Unlock()

		handshake := map[string]interface{}{
			"method":      "handShake",
			"auth":        n.client.Auth,
			"api_version": "6",
			"data":        "",
		}
		if err := conn.WriteJSON(handshake); err != nil {
			log.Printf("[rubingo] Handshake failed: %v", err)
			conn.Close()
			time.Sleep(3 * time.Second)
			continue
		}

		for {
			select {
			case <-stopCh:
				conn.Close()
				return
			default:
			}

			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[rubingo] WSS read error: %v", err)
				conn.Close()
				time.Sleep(3 * time.Second)
				break
			}

			var msgData map[string]interface{}
			if err := json.Unmarshal(message, &msgData); err != nil {
				continue
			}

			go n.handleTextMessage(msgData)
		}
	}
}

func (n *Network) keepSocket(stopCh <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			n.wsMu.Lock()
			ws := n.wsConn
			n.wsMu.Unlock()
			if ws != nil {
				if err := ws.WriteJSON(map[string]interface{}{}); err != nil {
					log.Printf("[rubingo] Keep-alive failed: %v", err)
				}
				go func() {
					if _, err := n.client.GetChatsUpdates(); err != nil {
						log.Printf("[rubingo] GetChatsUpdates error: %v", err)
					}
				}()
			}
		}
	}
}

func (n *Network) handleTextMessage(msgData map[string]interface{}) {
	dataEnc, ok := msgData["data_enc"].(string)
	if !ok || dataEnc == "" {
		return
	}
	decrypted, err := n.cryptoHelper.Decrypt(dataEnc, n.client.Key)
	if err != nil {
		log.Printf("[rubingo] Decrypt error: %v", err)
		return
	}
	userGUID, _ := decrypted["user_guid"].(string)
	delete(decrypted, "user_guid")
	for name, updates := range decrypted {
		updateList, ok := updates.([]interface{})
		if !ok {
			continue
		}
		for _, upd := range updateList {
			updMap, ok := upd.(map[string]interface{})
			if !ok {
				continue
			}
			updMap["client"] = n.client
			updMap["user_guid"] = userGUID
			n.handleUpdate(name, updMap)
		}
	}
}

func (n *Network) handleUpdate(name string, updateData map[string]interface{}) {
	capitalizedName := capitalizeStr(name)
	n.client.handlersMu.RLock()
	defer n.client.handlersMu.RUnlock()
	for _, handler := range n.client.handlers {
		if handler.Name != capitalizedName {
			continue
		}
		if handler.Filter != nil && !handler.Filter(updateData) {
			continue
		}
		update := NewUpdate(updateData)
		update.Client = n.client
		if handler.Func != nil {
			if n.client.SequentialHandlers {
				handler.Func(update)
				break
			} else {
				go handler.Func(update)
			}
		}
	}
}

func (n *Network) UploadFile(file interface{}, fileName string, mimeType string, chunk int, callback func(total, current int64)) (*Update, error) {
	var fileData []byte
	var fileSize int64

	switch f := file.(type) {
	case string:
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("file not found: %w", err)
		}
		fileData = data
		fileSize = int64(len(data))
		if fileName == "" {
			fileName = filepath.Base(f)
		}
	case []byte:
		if fileName == "" {
			return nil, errors.New("file_name must be specified when uploading from bytes")
		}
		fileData = f
		fileSize = int64(len(f))
	default:
		return nil, errors.New("file must be a file path (string) or raw bytes")
	}

	if mimeType == "" {
		ext := filepath.Ext(fileName)
		if ext != "" {
			mimeType = ext[1:]
		}
	}
	if chunk <= 0 {
		chunk = DefaultChunkSize
	}

	result, err := n.client.RequestSendFile(fileName, fileSize, mimeType)
	if err != nil {
		return nil, err
	}

	fileID := result.GetString("id")
	dcID := result.GetString("dc_id")
	uploadURL := result.GetString("upload_url")
	accessHashSend := result.GetString("access_hash_send")
	totalParts := (fileSize + int64(chunk) - 1) / int64(chunk)

	var uploadResult map[string]interface{}

	for index := int64(0); index < totalParts; index++ {
		start := index * int64(chunk)
		end := start + int64(chunk)
		if end > fileSize {
			end = fileSize
		}
		chunkData := fileData[start:end]

		for attempt := 0; attempt < n.maxRetries; attempt++ {
			req, err := http.NewRequest("POST", uploadURL, bytes.NewReader(chunkData))
			if err != nil {
				continue
			}
			req.Header.Set("auth", n.client.Auth)
			req.Header.Set("file-id", fileID)
			req.Header.Set("total-part", fmt.Sprintf("%d", totalParts))
			req.Header.Set("part-number", fmt.Sprintf("%d", index+1))
			req.Header.Set("chunk-size", fmt.Sprintf("%d", len(chunkData)))
			req.Header.Set("access-hash-send", accessHashSend)

			resp, err := n.getClientFor(ProxyOpUpload).Do(req)
			if err != nil {
				if attempt < n.maxRetries-1 {
					time.Sleep(exponentialBackoff(attempt))
					continue
				}
				return nil, err
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			if err := json.Unmarshal(body, &uploadResult); err != nil {
				continue
			}

			if status, _ := uploadResult["status"].(string); status == "ERROR_TRY_AGAIN" {
				result, err = n.client.RequestSendFile(fileName, fileSize, mimeType)
				if err != nil {
					return nil, err
				}
				fileID = result.GetString("id")
				dcID = result.GetString("dc_id")
				uploadURL = result.GetString("upload_url")
				accessHashSend = result.GetString("access_hash_send")
				index = -1
				break
			}
			break
		}

		if callback != nil {
			current := end
			if current > fileSize {
				current = fileSize
			}
			callback(fileSize, current)
		}
	}

	if uploadResult != nil {
		status, _ := uploadResult["status"].(string)
		statusDet, _ := uploadResult["status_det"].(string)
		if status == "OK" && statusDet == "OK" {
			dataMap, _ := uploadResult["data"].(map[string]interface{})
			accessHashRec := ""
			if dataMap != nil {
				accessHashRec, _ = dataMap["access_hash_rec"].(string)
			}
			return NewUpdate(map[string]interface{}{
				"mime":            mimeType,
				"size":            fileSize,
				"dc_id":           dcID,
				"file_id":         fileID,
				"file_name":       fileName,
				"access_hash_rec": accessHashRec,
			}), nil
		}
	}

	return nil, fmt.Errorf("upload failed: %v", uploadResult)
}

func (n *Network) Download(dcID, fileID, accessHash string, size int64, chunk int, callback func(total, current int64), saveAs string) ([]byte, error) {
	if chunk <= 0 {
		chunk = DownloadChunk
	}
	baseURL := fmt.Sprintf("https://messenger%s.iranlms.ir", dcID)

	if saveAs != "" {
		f, err := os.Create(saveAs)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		for start := int64(0); start < size; start += int64(chunk) {
			end := start + int64(chunk)
			if end > size {
				end = size
			}
			data, err := n.fetchChunk(baseURL, fileID, accessHash, start, end-1)
			if err != nil {
				return nil, err
			}
			if _, err := f.Write(data); err != nil {
				return nil, err
			}
			if callback != nil {
				callback(size, end)
			}
		}
		return nil, nil
	}

	var result []byte
	for start := int64(0); start < size; start += int64(chunk) {
		end := start + int64(chunk)
		if end > size {
			end = size
		}
		data, err := n.fetchChunk(baseURL, fileID, accessHash, start, end-1)
		if err != nil {
			return nil, err
		}
		result = append(result, data...)
		if callback != nil {
			callback(size, int64(len(result)))
		}
	}
	return result, nil
}

func (n *Network) fetchChunk(baseURL, fileID, accessHash string, start, end int64) ([]byte, error) {
	for attempt := 0; attempt < n.maxRetries; attempt++ {
		req, err := http.NewRequest("POST", baseURL+"/GetFile.ashx", nil)
		if err != nil {
			continue
		}
		req.Header.Set("auth", n.client.Auth)
		req.Header.Set("access-hash-rec", accessHash)
		req.Header.Set("file-id", fileID)
		req.Header.Set("user-agent", n.client.UserAgent)
		req.Header.Set("start-index", fmt.Sprintf("%d", start))
		req.Header.Set("last-index", fmt.Sprintf("%d", end))

		resp, err := n.getClientFor(ProxyOpDownload).Do(req)
		if err != nil {
			time.Sleep(exponentialBackoff(attempt))
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			return data, nil
		}
	}
	return nil, errors.New("download chunk failed after retries")
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Handler
// ═══════════════════════════════════════════════════════════════════════════════

type Handler struct {
	Name   string
	Func   func(*Update)
	Filter func(map[string]interface{}) bool
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//	RubClient
//
// ═══════════════════════════════════════════════════════════════════════════════
type RubClient struct {
	Name               string
	Auth               string
	GUID               string
	Key                string
	DecodeAuthStr      string
	PrivateKey         string
	ImportKey          *rsa.PrivateKey
	PhoneNumber        string
	UserAgent          string
	LangCode           string
	Timeout            time.Duration
	ParseMode          string
	Proxy              string
	ProxyEnabled       bool
	ProxyExclude       map[string]bool // عملیات‌هایی که از پروکسی استثنا هستند
	APIVersion         string
	MaxRetries         int
	SequentialHandlers bool
	DisplayWelcome     bool
	URLCacheFile       string

	SessionMode    SessionMode
	OnSessionSaved func(data SessionData)

	DefaultPlatform map[string]string

	session        Session
	connection     *Network
	cryptoHelper   *CryptoHelper
	markdown       *MarkdownParser
	mediaThumbnail *MediaThumbnail
	audio          *Audio
	handlers       []Handler
	handlersMu     sync.RWMutex
	stopCh         chan struct{}
	logger         *log.Logger
}

type ClientOption func(*RubClient)

func WithAuth(auth string) ClientOption        { return func(c *RubClient) { c.Auth = auth } }
func WithPrivateKey(pk string) ClientOption    { return func(c *RubClient) { c.PrivateKey = pk } }
func WithPhoneNumber(pn string) ClientOption   { return func(c *RubClient) { c.PhoneNumber = pn } }
func WithUserAgent(ua string) ClientOption     { return func(c *RubClient) { c.UserAgent = ua } }
func WithTimeout(t time.Duration) ClientOption { return func(c *RubClient) { c.Timeout = t } }
func WithLangCode(lc string) ClientOption      { return func(c *RubClient) { c.LangCode = lc } }
func WithParseMode(pm string) ClientOption     { return func(c *RubClient) { c.ParseMode = pm } }
func WithMaxRetries(mr int) ClientOption       { return func(c *RubClient) { c.MaxRetries = mr } }
func WithDisplayWelcome(dw bool) ClientOption  { return func(c *RubClient) { c.DisplayWelcome = dw } }
func WithURLCacheFile(f string) ClientOption   { return func(c *RubClient) { c.URLCacheFile = f } }

// ═══════════════════════════════════════════════════════════════════════════════
//  Proxy Options
// ═══════════════════════════════════════════════════════════════════════════════

// WithProxy آدرس پروکسی را تنظیم می‌کند (فقط یک بار!)
func WithProxy(proxyURL string) ClientOption {
	return func(c *RubClient) {
		c.Proxy = proxyURL
	}
}

// WithProxyEnabled پروکسی را فعال یا غیرفعال می‌کند
func WithProxyEnabled(enabled bool) ClientOption {
	return func(c *RubClient) {
		c.ProxyEnabled = enabled
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Proxy Exclude Options & Methods
// ═══════════════════════════════════════════════════════════════════════════════

// WithProxyExclude مشخص می‌کند کدام عملیات‌ها هرگز از پروکسی استفاده نکنند
// مثال: WithProxyExclude(rubingo.ProxyOpRefreshURL, rubingo.ProxyOpGetDCs)
func WithProxyExclude(operations ...string) ClientOption {
	return func(c *RubClient) {
		if c.ProxyExclude == nil {
			c.ProxyExclude = make(map[string]bool)
		}
		for _, op := range operations {
			c.ProxyExclude[op] = true
		}
	}
}

// ExcludeFromProxy یک یا چند عملیات را از استفاده پروکسی منع می‌کند
// حتی اگر پروکسی فعال باشد، این عملیات‌ها مستقیم (بدون پروکسی) اجرا می‌شوند
func (c *RubClient) ExcludeFromProxy(operations ...string) {
	if c.ProxyExclude == nil {
		c.ProxyExclude = make(map[string]bool)
	}
	for _, op := range operations {
		c.ProxyExclude[op] = true
		log.Printf("[rubingo] Operation '%s' excluded from proxy", op)
	}
}

// IncludeInProxy یک عملیات را دوباره اجازه استفاده از پروکسی می‌دهد
func (c *RubClient) IncludeInProxy(operations ...string) {
	if c.ProxyExclude == nil {
		return
	}
	for _, op := range operations {
		delete(c.ProxyExclude, op)
		log.Printf("[rubingo] Operation '%s' included in proxy again", op)
	}
}

// IsExcludedFromProxy بررسی می‌کند که آیا یک عملیات از پروکسی استثنا شده
func (c *RubClient) IsExcludedFromProxy(operation string) bool {
	if c.ProxyExclude == nil {
		return false
	}
	return c.ProxyExclude[operation]
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Session Options
// ═══════════════════════════════════════════════════════════════════════════════

func WithSessionCallback(fn func(SessionData)) ClientOption {
	return func(c *RubClient) {
		c.SessionMode = SessionModeCallback
		c.OnSessionSaved = fn
	}
}

func WithPlatform(p string) ClientOption {
	return func(c *RubClient) {
		if strings.EqualFold(p, "android") {
			c.DefaultPlatform["platform"] = "Android"
		}
	}
}

func WithSequentialHandlers(sh bool) ClientOption {
	return func(c *RubClient) { c.SequentialHandlers = sh }
}

func WithStringSession(ss *StringSession) ClientOption {
	return func(c *RubClient) { c.session = ss }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Proxy Runtime Methods
// ═══════════════════════════════════════════════════════════════════════════════

// SetProxy آدرس پروکسی را تنظیم می‌کند
func (c *RubClient) SetProxy(proxyURL string) {
	c.Proxy = proxyURL
	if c.connection != nil {
		c.connection.updateProxy(proxyURL, c.ProxyEnabled)
	}
}

// EnableProxy پروکسی را فعال می‌کند
func (c *RubClient) EnableProxy() {
	c.ProxyEnabled = true
	if c.connection != nil {
		c.connection.updateProxy(c.Proxy, true)
	}
}

// DisableProxy پروکسی را غیرفعال می‌کند
func (c *RubClient) DisableProxy() {
	c.ProxyEnabled = false
	if c.connection != nil {
		c.connection.updateProxy(c.Proxy, false)
	}
}

// IsProxyEnabled برمی‌گرداند که آیا پروکسی فعال است
func (c *RubClient) IsProxyEnabled() bool {
	return c.ProxyEnabled && c.Proxy != ""
}

func NewClient(name string, opts ...ClientOption) (*RubClient, error) {
	c := &RubClient{
		Name:         name,
		UserAgent:    DefaultUserAgent,
		LangCode:     "fa",
		Timeout:      DefaultTimeout,
		ParseMode:    "markdown",
		APIVersion:   DefaultAPIVersion,
		MaxRetries:   5,
		ProxyExclude: make(map[string]bool),
		URLCacheFile: URLCacheFile,
		DefaultPlatform: map[string]string{
			"app_name":    "Main",
			"app_version": "2.4.6",
			"platform":    "PWA",
			"package":     "m.rubika.ir",
		},
		cryptoHelper:   NewCrypto(),
		markdown:       NewMarkdownParser(),
		mediaThumbnail: NewMediaThumbnail(),
		audio:          NewAudio(),
		logger:         log.New(os.Stdout, "[rubingo] ", log.LstdFlags),
		stopCh:         make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	c.DefaultPlatform["lang_code"] = c.LangCode

	// Create session based on mode
	if c.session == nil {
		switch c.SessionMode {
		case SessionModeCallback:
			c.session = &NoOpSession{}
		default:
			session, err := NewSQLiteSession(name)
			if err != nil {
				return nil, fmt.Errorf("failed to create session: %w", err)
			}
			c.session = session
		}
	}

	if c.DisplayWelcome {
		c.logger.Println("Rubika client initialized successfully.")
	}

	return c, nil
}

func NewClientWithStringSession(sessionString string, opts ...ClientOption) (*RubClient, error) {
	ss, err := NewStringSession(sessionString)
	if err != nil {
		return nil, err
	}
	opts = append(opts, WithStringSession(ss))
	return NewClient("string_session", opts...)
}

func (c *RubClient) Connect() error {
	c.connection = NewNetwork(c)
	info := c.session.Information()
	if info != nil {
		c.Auth = info.Auth
		c.GUID = info.GUID
		c.PrivateKey = info.PrivateKey
		if info.UserAgent != "" {
			c.UserAgent = info.UserAgent
		}
		c.logger.Printf("Session loaded: auth=%s guid=%s", truncate(c.Auth, 8), c.GUID)
	}
	return nil
}

func (c *RubClient) Builder(name string, tmpSession bool, encrypt bool, input map[string]interface{}) (*Update, error) {
	if c.connection == nil {
		return nil, ErrNoConnection
	}

	if c.connection.apiURL == "" {
		if err := c.connection.GetDCs(); err != nil {
			return nil, fmt.Errorf("failed to get DCs: %w", err)
		}
	}

	if c.Auth == "" {
		c.Auth = c.cryptoHelper.Secret(32)
		c.logger.Printf("Created auth secret: %s", truncate(c.Auth, 8))
	}

	if c.Key == "" {
		c.Key = c.cryptoHelper.Passphrase(c.Auth)
	}

	if c.DecodeAuthStr == "" && c.Auth != "" {
		c.DecodeAuthStr = c.cryptoHelper.DecodeAuth(c.Auth)
	}

	if input == nil {
		input = make(map[string]interface{})
	}

	result, err := c.connection.Send(SendOpts{
		Method:     name,
		TmpSession: tmpSession,
		Encrypt:    encrypt,
		Input:      input,
	})
	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, errors.New("nil response from server")
	}

	if dataEnc, ok := result["data_enc"].(string); ok {
		decrypted, err := c.cryptoHelper.Decrypt(dataEnc, c.Key)
		if err != nil {
			return nil, fmt.Errorf("decrypt error: %w", err)
		}
		result = decrypted
	}

	status, _ := result["status"].(string)
	statusDet, _ := result["status_det"].(string)

	if status == "OK" && statusDet == "OK" {
		data, _ := result["data"].(map[string]interface{})
		if data == nil {
			data = make(map[string]interface{})
		}
		data["_client"] = c
		return NewUpdate(data), nil
	}

	if statusDet == "NOT_REGISTERED" {
		return nil, ErrNotRegistered
	}

	return nil, &RequestError{Status: status, StatusDet: statusDet, Data: result}
}

// ─── API Methods ─────────────────────────────────────────────────────────────

func (c *RubClient) GetUserInfo(userGUID string) (*Update, error) {
	input := make(map[string]interface{})
	if userGUID != "" {
		input["user_guid"] = userGUID
	}
	tmpSession := c.ImportKey == nil
	return c.Builder("getUserInfo", tmpSession, true, input)
}

func (c *RubClient) GetMe() (*Update, error) { return c.GetUserInfo("") }

func (c *RubClient) SendCode(phoneNumber, passKey, sendType string) (*Update, error) {
	if sendType == "" {
		sendType = "SMS"
	}
	if sendType != "SMS" && sendType != "Internal" {
		return nil, errors.New("send_type can only be 'SMS' or 'Internal'")
	}
	input := map[string]interface{}{
		"phone_number": phoneNumber,
		"send_type":    sendType,
	}
	if passKey != "" {
		input["pass_key"] = passKey
	}
	return c.Builder("sendCode", true, true, input)
}

// ApplySignInResult updates the client's internal state with data from SignInExt.
// Call this after a successful SignInExt before making any API calls.
// ApplySignInResult updates the client's internal state with data from SignInExt
// and returns the session data for external storage.
func (c *RubClient) ApplySignInResult(result *SignInResult) (SessionData, error) {
	// ═══════════════════════════════════════════════════════
	// ۱. به‌روزرسانی حافظه موقت (RAM)
	// ═══════════════════════════════════════════════════════
	c.Auth = result.Auth
	c.Key = c.cryptoHelper.Passphrase(c.Auth)
	c.DecodeAuthStr = c.cryptoHelper.DecodeAuth(c.Auth)
	c.GUID = result.UserGUID
	c.PrivateKey = result.PrivateKey
	c.PhoneNumber = result.PhoneNumber

	if c.PrivateKey != "" {
		key, err := parsePrivateKey(c.PrivateKey)
		if err == nil {
			c.ImportKey = key
		}
	}

	// ═══════════════════════════════════════════════════════
	// ۲. ساخت SessionData برای return
	// ═══════════════════════════════════════════════════════
	sessionData := SessionData{
		Auth:        c.Auth,
		GUID:        c.GUID,
		UserAgent:   c.UserAgent,
		PhoneNumber: c.PhoneNumber,
		PrivateKey:  c.PrivateKey,
	}

	// ═══════════════════════════════════════════════════════
	// ۳. ذخیره سشن (فایل یا callback)
	// ═══════════════════════════════════════════════════════
	c.saveSession(c.Auth, c.GUID, c.UserAgent, c.PhoneNumber, c.PrivateKey)

	// ═══════════════════════════════════════════════════════
	// ۴. ثبت دستگاه در روبیکا
	// ═══════════════════════════════════════════════════════
	c.RegisterDevice(c.Name)

	return sessionData, nil
}

// SendCodeExt sends a verification code and returns the raw phone_code_hash and
// tmp_session needed for external login flows (e.g. when you manage auth yourself).
//
// phoneNumber should be in international format (e.g. "989123456789").
// passKey is the 2FA password — pass empty string if not needed.
//
// If Rubika responds with SendPassKey, the returned SendCodeResult will have
// AuthStatus set with ErrSendPassKey so you can prompt the user and retry with passKey.
func (c *RubClient) SendCodeExt(phoneNumber, passKey string) (*SendCodeResult, error) {
	if c.connection == nil {
		return nil, ErrNoConnection
	}

	if c.connection.apiURL == "" {
		if err := c.connection.GetDCs(); err != nil {
			return nil, err
		}
	}

	// Generate a fresh tmp auth for this send attempt
	tmpAuth := c.cryptoHelper.Secret(32)
	tmpKey := c.cryptoHelper.Passphrase(tmpAuth)

	input := map[string]interface{}{
		"phone_number": phoneNumber,
		"send_type":    "SMS",
	}
	if passKey != "" {
		input["pass_key"] = passKey
	}

	dataToEnc := map[string]interface{}{
		"method": "sendCode",
		"input":  input,
		"client": c.DefaultPlatform,
	}

	encrypted, err := c.cryptoHelper.Encrypt(dataToEnc, tmpKey)
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"api_version": c.APIVersion,
		"tmp_session": tmpAuth, // ✅ خام! نه DecodeAuth شده
		"data_enc":    encrypted,
	}

	raw, err := c.connection.doRequest(payload)
	if err != nil {
		return nil, err
	}

	// Decrypt response
	var responseData map[string]interface{}
	if dataEnc, ok := raw["data_enc"].(string); ok {
		decrypted, err := c.cryptoHelper.Decrypt(dataEnc, tmpKey)
		if err == nil {
			responseData = decrypted
		} else {
			responseData = raw
		}
	} else {
		responseData = raw
	}

	// Check for 2FA / error conditions
	if authStatus := AnalyzeAuthResponse(responseData); authStatus != nil {
		return &SendCodeResult{
			TmpSession: tmpAuth, // ✅ خام
			AuthStatus: authStatus,
			Status:     authStatus.Status,
		}, authStatus.Err
	}

	// Extract phone_code_hash
	data, _ := responseData["data"].(map[string]interface{})
	if data == nil {
		data = responseData
	}

	phoneCodeHash, _ := data["phone_code_hash"].(string)
	dataStatus, _ := data["status"].(string)

	return &SendCodeResult{
		PhoneCodeHash: phoneCodeHash,
		TmpSession:    tmpAuth, // ✅ خام
		Status:        dataStatus,
	}, nil
}

func (c *RubClient) SignIn(phoneCode, phoneNumber, phoneCodeHash, publicKey string) (*Update, error) {
	return c.Builder("signIn", true, true, map[string]interface{}{
		"phone_code":      phoneCode,
		"phone_number":    phoneNumber,
		"phone_code_hash": phoneCodeHash,
		"public_key":      publicKey,
	})
}

// SignInExt signs in with the given code and returns a structured SignInResult
// with all data needed for external storage (auth, user_guid, name, etc.).
//
// tmpSession and phoneCodeHash are the values returned by SendCodeExt.
// If tmpSession is empty, the client's current auth/key will be used.
// If phoneCodeHash is empty, the value from the last SendCode call is used.
func (c *RubClient) SignInExt(phoneCode, phoneNumber, phoneCodeHash, tmpSession string) (*SignInResult, error) {
	if c.connection == nil {
		return nil, ErrNoConnection
	}

	// Generate RSA key pair for this sign-in
	publicKey, privateKey, err := c.cryptoHelper.CreateKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA keys: %w", err)
	}

	// Determine which session/key to use for encryption
	var encKey string
	var sessionToken string

	if tmpSession != "" {
		sessionToken = tmpSession
		// Derive the AES key from the decoded tmp session
		// tmpSession is already the decoded form (changeAuthType applied)
		encKey = c.cryptoHelper.Passphrase(
			// The passphrase function expects the raw 32-char auth, but tmpSession
			// from SendCodeExt is already decoded. We use the raw key directly.
			// We re-derive by reversing DecodeAuth on tmpSession to get the raw form,
			// but since DecodeAuth is its own inverse-like transform, we just use
			// the stored key from SendCodeExt if available.
			// For simplicity: regenerate key from tmpSession treated as auth.
			tmpSession,
		)
		// If tmpSession length != 32, fallback to client key
		if len(tmpSession) != 32 {
			encKey = c.Key
		}
	} else {
		sessionToken = c.DecodeAuthStr
		encKey = c.Key
	}

	if encKey == "" {
		return nil, errors.New("no encryption key available; call SendCodeExt or Connect first")
	}

	input := map[string]interface{}{
		"phone_code":      phoneCode,
		"phone_number":    phoneNumber,
		"phone_code_hash": phoneCodeHash,
		"public_key":      publicKey,
	}

	dataToEnc := map[string]interface{}{
		"method": "signIn",
		"input":  input,
		"client": c.DefaultPlatform,
	}

	encrypted, err := c.cryptoHelper.Encrypt(dataToEnc, encKey)
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"api_version": c.APIVersion,
		"tmp_session": sessionToken,
		"data_enc":    encrypted,
	}

	raw, err := c.connection.doRequest(payload)
	if err != nil {
		return nil, err
	}

	// Decrypt response
	var responseData map[string]interface{}
	if dataEnc, ok := raw["data_enc"].(string); ok {
		decrypted, err := c.cryptoHelper.Decrypt(dataEnc, encKey)
		if err == nil {
			responseData = decrypted
		} else {
			responseData = raw
		}
	} else {
		responseData = raw
	}

	// Check for auth-related errors (wrong code, etc.)
	if authStatus := AnalyzeAuthResponse(responseData); authStatus != nil {
		return nil, authStatus.Err
	}

	data, _ := responseData["data"].(map[string]interface{})
	if data == nil {
		data = responseData
	}

	dataStatus, _ := data["status"].(string)
	if dataStatus != "OK" {
		return nil, fmt.Errorf("signIn failed with status: %s", dataStatus)
	}

	// Decrypt the auth token with our RSA private key
	encAuth, _ := data["auth"].(string)
	if encAuth == "" {
		return nil, errors.New("auth token missing from response")
	}

	decryptedAuth, err := c.cryptoHelper.DecryptRSAOAEP(privateKey, encAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth token: %w", err)
	}

	// Extract user info
	result := &SignInResult{
		Auth:       decryptedAuth,
		PrivateKey: privateKey,
	}

	if user, ok := data["user"].(map[string]interface{}); ok {
		result.RawUser = user
		result.UserGUID, _ = user["user_guid"].(string)
		result.FirstName, _ = user["first_name"].(string)
		result.LastName, _ = user["last_name"].(string)
		result.Username, _ = user["username"].(string)
		result.PhoneNumber, _ = user["phone"].(string)
	}

	return result, nil
}

func (c *RubClient) RegisterDevice(deviceModel string) (*Update, error) {
	input := c.getBrowserPlatform(deviceModel)
	return c.Builder("registerDevice", false, true, input)
}

func (c *RubClient) getBrowserPlatform(deviceModel string) map[string]interface{} {
	ua := c.UserAgent
	var dm string
	re := regexp.MustCompile(`(?i)(opera|chrome|safari|firefox|msie|trident)/(\d+)`)
	match := re.FindStringSubmatch(strings.ToLower(ua))
	if len(match) >= 3 {
		dm = strings.Title(match[1]) + " " + match[2]
	} else {
		dm = "Unknown"
	}
	systemVersion := "Unknown"
	sysVersions := map[string]string{
		"Windows NT 10.0": "Windows 10", "Windows NT 6.2": "Windows 8",
		"Windows NT 6.1": "Windows 7", "Windows NT 6.0": "Windows Vista",
		"Windows NT 5.1": "Windows XP", "Windows NT 5.0": "Windows 2000",
		"Mac": "Mac/iOS", "X11": "UNIX", "Linux": "Linux",
	}
	for key, value := range sysVersions {
		if strings.Contains(ua, key) {
			systemVersion = value
			break
		}
	}
	if deviceModel != "" {
		dm = deviceModel
	}
	digitRE := regexp.MustCompile(`\d+`)
	digits := strings.Join(digitRE.FindAllString(ua, -1), "")
	return map[string]interface{}{
		"token": "", "lang_code": c.LangCode, "token_type": "Firebase",
		"app_version":    "PW_" + c.DefaultPlatform["app_version"],
		"system_version": systemVersion, "device_model": dm,
		"device_hash": "2" + digits,
	}
}

func (c *RubClient) RequestSendFile(fileName string, fileSize int64, mimeType string) (*Update, error) {
	return c.Builder("requestSendFile", false, true, map[string]interface{}{
		"file_name": fileName, "size": fileSize, "mime": mimeType,
	})
}

func (c *RubClient) GetChatsUpdates() (*Update, error) {
	return c.Builder("getChatsUpdates", false, true, map[string]interface{}{
		"state": time.Now().Unix(),
	})
}

func (c *RubClient) DeleteMessages(objectGUID string, messageIDs []string) (*Update, error) {
	return c.Builder("deleteMessages", false, true, map[string]interface{}{
		"object_guid": objectGUID, "message_ids": messageIDs,
	})
}

func (c *RubClient) ForwardMessages(fromObjectGUID, toObjectGUID string, messageIDs []string) (*Update, error) {
	return c.Builder("forwardMessages", false, true, map[string]interface{}{
		"from_object_guid": fromObjectGUID, "to_object_guid": toObjectGUID, "message_ids": messageIDs,
	})
}

func (c *RubClient) EditMessage(objectGUID, messageID, text string) (*Update, error) {
	return c.Builder("editMessage", false, true, map[string]interface{}{
		"object_guid": objectGUID, "message_id": messageID, "text": text,
	})
}

func (c *RubClient) GetMessagesByID(objectGUID string, messageIDs interface{}) (*Update, error) {
	var ids []string
	switch v := messageIDs.(type) {
	case string:
		ids = []string{v}
	case []string:
		ids = v
	case []interface{}:
		for _, id := range v {
			ids = append(ids, fmt.Sprintf("%v", id))
		}
	}
	return c.Builder("getMessagesByID", false, true, map[string]interface{}{
		"object_guid": objectGUID, "message_ids": ids,
	})
}

func (c *RubClient) SetPinMessage(objectGUID, messageID, action string) (*Update, error) {
	return c.Builder("setPinMessage", false, true, map[string]interface{}{
		"object_guid": objectGUID, "message_id": messageID, "action": action,
	})
}

func (c *RubClient) GetGroupInfo(groupGUID string) (*Update, error) {
	return c.Builder("getGroupInfo", false, true, map[string]interface{}{"group_guid": groupGUID})
}

func (c *RubClient) GetChannelInfo(channelGUID string) (*Update, error) {
	return c.Builder("getChannelInfo", false, true, map[string]interface{}{"channel_guid": channelGUID})
}

func (c *RubClient) SendChatActivity(objectGUID, activity string) (*Update, error) {
	return c.Builder("sendChatActivity", false, true, map[string]interface{}{
		"object_guid": objectGUID, "activity": activity,
	})
}

func (c *RubClient) ActionOnMessageReaction(objectGUID, messageID, action string, reactionID int) (*Update, error) {
	return c.Builder("actionOnMessageReaction", false, true, map[string]interface{}{
		"object_guid": objectGUID, "message_id": messageID, "action": action, "reaction_id": reactionID,
	})
}

func (c *RubClient) BanGroupMember(objectGUID, userGUID, action string) (*Update, error) {
	if action == "" {
		action = "Set"
	}
	return c.Builder("banGroupMember", false, true, map[string]interface{}{
		"group_guid": objectGUID, "member_guid": userGUID, "action": action,
	})
}

func (c *RubClient) BanChannelMember(objectGUID, userGUID, action string) (*Update, error) {
	if action == "" {
		action = "Set"
	}
	return c.Builder("banChannelMember", false, true, map[string]interface{}{
		"channel_guid": objectGUID, "member_guid": userGUID, "action": action,
	})
}

func (c *RubClient) GetGroupAdminMembers(groupGUID string) (*Update, error) {
	return c.Builder("getGroupAdminMembers", false, true, map[string]interface{}{"group_guid": groupGUID})
}

func (c *RubClient) GetChannelAdminMembers(channelGUID string) (*Update, error) {
	return c.Builder("getChannelAdminMembers", false, true, map[string]interface{}{"channel_guid": channelGUID})
}

func (c *RubClient) SeenChats(seenList map[string]string) (*Update, error) {
	var seenArr []map[string]string
	for guid, msgID := range seenList {
		seenArr = append(seenArr, map[string]string{"object_guid": guid, "message_id": msgID})
	}
	return c.Builder("seenChats", false, true, map[string]interface{}{"seen_list": seenArr})
}

func (c *RubClient) SetBlockUser(userGUID string) (*Update, error) {
	return c.Builder("setBlockUser", false, true, map[string]interface{}{"user_guid": userGUID, "action": "Block"})
}

func (c *RubClient) UnblockUser(userGUID string) (*Update, error) {
	return c.Builder("setBlockUser", false, true, map[string]interface{}{"user_guid": userGUID, "action": "Unblock"})
}

func (c *RubClient) GetInfo(objectGUID string) (*Update, error) {
	if strings.HasPrefix(objectGUID, "g0") {
		return c.GetGroupInfo(objectGUID)
	} else if strings.HasPrefix(objectGUID, "c0") {
		return c.GetChannelInfo(objectGUID)
	}
	return c.GetUserInfo(objectGUID)
}

// ─── SendMessage ─────────────────────────────────────────────────────────────

type SendMessageOptions struct {
	ObjectGUID       string
	Text             string
	ReplyToMessageID string
	FileInline       interface{}
	Sticker          interface{}
	Type             string
	IsSpoil          bool
	Thumb            bool
	AudioInfo        bool
	AutoDelete       float64
	ParseMode        string
	Metadata         interface{}
	FileName         string
	Time             int
	Width            int
	Height           int
	Performer        string
}

func (c *RubClient) SendMessage(opts SendMessageOptions) (*Update, error) {
	if c.connection == nil {
		return nil, ErrNoConnection
	}

	objectGUID := opts.ObjectGUID
	lower := strings.ToLower(objectGUID)
	if lower == "me" || lower == "cloud" || lower == "self" {
		objectGUID = c.GUID
	}

	if opts.Type == "" {
		opts.Type = "File"
	}

	if opts.FileInline != nil {
		if !opts.Thumb {
			opts.Thumb = true
		}
		if !opts.AudioInfo {
			opts.AudioInfo = true
		}
	}

	rnd := mathrand.Intn(1000000) + 1
	inputData := map[string]interface{}{
		"object_guid": objectGUID,
		"rnd":         fmt.Sprintf("%d", rnd),
	}

	if opts.ReplyToMessageID != "" {
		inputData["reply_to_message_id"] = opts.ReplyToMessageID
	}

	if opts.Text != "" {
		inputData["text"] = strings.TrimSpace(opts.Text)
		parseMode := opts.ParseMode
		if parseMode == "" {
			parseMode = c.ParseMode
		}
		if parseMode != "" {
			var mdResult MetadataResult
			if parseMode == "html" {
				mdText := c.markdown.ToMarkdown(opts.Text)
				mdResult = c.markdown.ToMetadata(mdText)
			} else {
				mdResult = c.markdown.ToMetadata(opts.Text)
			}
			inputData["text"] = mdResult.Text
			if mdResult.Metadata != nil {
				metaJSON, _ := json.Marshal(mdResult.Metadata)
				var metaMap map[string]interface{}
				json.Unmarshal(metaJSON, &metaMap)
				inputData["metadata"] = metaMap
			}
		}
		if opts.Metadata != nil {
			switch m := opts.Metadata.(type) {
			case map[string]interface{}:
				if _, ok := m["metadata"]; ok {
					for k, v := range m {
						inputData[k] = v
					}
				} else {
					inputData["metadata"] = m
				}
			case *Update:
				for k, v := range m.Data {
					inputData[k] = v
				}
			}
		}
	}

	if opts.Sticker != nil {
		switch s := opts.Sticker.(type) {
		case *Update:
			inputData["sticker"] = s.Data
		case map[string]interface{}:
			inputData["sticker"] = s
		}
	}

	var fileInlineData map[string]interface{}
	var fileBytes []byte

	if opts.FileInline != nil {
		switch fi := opts.FileInline.(type) {
		case string:
			if strings.HasPrefix(fi, "http://") || strings.HasPrefix(fi, "https://") {
				resp, err := http.Get(fi)
				if err != nil {
					return nil, fmt.Errorf("failed to download file: %w", err)
				}
				data, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					return nil, err
				}
				if opts.FileName == "" {
					contentType := resp.Header.Get("Content-Type")
					exts, _ := mime.ExtensionsByType(contentType)
					ext := ""
					if len(exts) > 0 {
						ext = exts[0]
					} else {
						ext = "." + strings.ToLower(opts.Type)
					}
					opts.FileName = fmt.Sprintf("%d%s", rnd, ext)
				}
				fileBytes = data
			} else {
				data, err := os.ReadFile(fi)
				if err != nil {
					return nil, fmt.Errorf("failed to read file: %w", err)
				}
				if opts.FileName == "" {
					opts.FileName = filepath.Base(fi)
				}
				fileBytes = data
			}
		case []byte:
			if opts.FileName == "" {
				opts.FileName = fmt.Sprintf("%d.%s", rnd, strings.ToLower(opts.Type))
			}
			fileBytes = fi
		case *Update:
			fileInlineData = fi.Data
		case map[string]interface{}:
			fileInlineData = fi
		}

		if fileBytes != nil {
			var thumb *ResultMedia
			var audioInfo *AudioResult

			if opts.Type == "Music" || opts.Type == "Voice" {
				if opts.AudioInfo {
					audioInfo = c.audio.GetAudioInfo(fileBytes)
				}
			} else if opts.Thumb {
				switch opts.Type {
				case "Video", "Gif", "VideoMessage":
					thumb = c.mediaThumbnail.FromVideo(fileBytes)
				case "Image":
					thumb = c.mediaThumbnail.FromImage(fileBytes)
				}
			}

			if opts.Thumb && thumb != nil && !thumb.HasImage() {
				if opts.Type != "Music" && opts.Type != "Voice" && opts.Type != "File" {
					opts.Type = "File"
					thumb = nil
				}
			}

			uploaded, err := c.Upload(fileBytes, opts.FileName, "")
			if err != nil {
				return nil, err
			}
			fileInlineData = uploaded.Data

			fileType := opts.Type
			if fileType == "VideoMessage" {
				fileInlineData["is_round"] = true
				fileType = "Video"
			}
			fileInlineData["type"] = fileType

			setDefault := func(key string, val interface{}) {
				if _, ok := fileInlineData[key]; !ok {
					fileInlineData[key] = val
				}
			}

			if opts.Time > 0 {
				fileInlineData["time"] = opts.Time
			} else {
				setDefault("time", 1)
			}
			if opts.Width > 0 {
				fileInlineData["width"] = opts.Width
			} else {
				setDefault("width", 200)
			}
			if opts.Height > 0 {
				fileInlineData["height"] = opts.Height
			} else {
				setDefault("height", 200)
			}
			if opts.Performer != "" {
				fileInlineData["music_performer"] = opts.Performer
			} else {
				setDefault("music_performer", "")
			}

			if thumb != nil && thumb.HasImage() {
				fileInlineData["time"] = thumb.Seconds
				fileInlineData["width"] = thumb.Width
				fileInlineData["height"] = thumb.Height
				fileInlineData["thumb_inline"] = thumb.ToBase64()
			}

			if audioInfo != nil {
				if opts.Performer == "" {
					fileInlineData["music_performer"] = audioInfo.Performer
				}
				if opts.Time == 0 {
					if opts.Type == "Music" {
						fileInlineData["time"] = audioInfo.Duration
					} else {
						fileInlineData["time"] = audioInfo.Duration * 1000
					}
				}
			}

			fileInlineData["is_spoil"] = opts.IsSpoil
		}

		if fileInlineData != nil {
			inputData["file_inline"] = fileInlineData
		}
	}

	var result *Update
	var err error

	if fileInlineData != nil {
		result, err = c.Builder("sendMessage", false, true, inputData)
	} else {
		if text, ok := inputData["text"].(string); ok && text != "" {
			chunks := splitText(text, 4200)
			if len(chunks) == 0 {
				result, err = c.Builder("sendMessage", false, true, inputData)
			} else {
				for _, chunk := range chunks {
					inputData["text"] = strings.TrimSpace(chunk)
					inputData["rnd"] = fmt.Sprintf("%d", mathrand.Intn(1000000)+1)
					result, err = c.Builder("sendMessage", false, true, inputData)
					if err != nil {
						return nil, err
					}
				}
			}
		} else {
			result, err = c.Builder("sendMessage", false, true, inputData)
		}
	}

	if err != nil {
		return nil, err
	}

	if opts.AutoDelete > 0 && result != nil {
		go func() {
			time.Sleep(time.Duration(opts.AutoDelete * float64(time.Second)))
			msgID := result.GetString("message_id")
			if msgID != "" {
				c.DeleteMessages(objectGUID, []string{msgID})
			}
		}()
	}

	return result, nil
}

func (c *RubClient) Upload(data []byte, fileName, mimeType string) (*Update, error) {
	return c.connection.UploadFile(data, fileName, mimeType, DefaultChunkSize, nil)
}

func (c *RubClient) DownloadFile(fileInline *Update, saveAs string) ([]byte, error) {
	if fileInline == nil {
		return nil, errors.New("file_inline is nil")
	}
	dcID := fileInline.GetString("dc_id")
	fileID := fileInline.GetString("file_id")
	accessHash := fileInline.GetString("access_hash_rec")
	sizeVal := fileInline.Get("size")
	var size int64
	switch s := sizeVal.(type) {
	case float64:
		size = int64(s)
	case int64:
		size = s
	case int:
		size = int64(s)
	case string:
		size, _ = strconv.ParseInt(s, 10, 64)
	}
	return c.connection.Download(dcID, fileID, accessHash, size, DownloadChunk, nil, saveAs)
}

// ─── Start / Run / Disconnect ─────────────────────────────────────────────────

func (c *RubClient) Start(phoneNumber string) error {
	if c.connection == nil {
		if err := c.Connect(); err != nil {
			return err
		}
	}

	if c.Auth != "" {
		c.DecodeAuthStr = c.cryptoHelper.DecodeAuth(c.Auth)
		c.Key = c.cryptoHelper.Passphrase(c.Auth)
	}

	if c.PrivateKey != "" {
		key, err := parsePrivateKey(c.PrivateKey)
		if err == nil {
			c.ImportKey = key
		}
	}

	result, err := c.GetMe()
	if err != nil {
		if isInvalidOrNotRegistered(err) {
			c.logger.Println("User not registered! Starting registration...")

			c.Auth = ""
			c.Key = ""
			c.DecodeAuthStr = ""
			c.ImportKey = nil

			if phoneNumber == "" {
				fmt.Print("Phone Number: ")
				fmt.Scanln(&phoneNumber)
				for {
					fmt.Printf("Is the %s correct? [y/n] > ", phoneNumber)
					var confirm string
					fmt.Scanln(&confirm)
					if strings.EqualFold(confirm, "y") {
						break
					}
					fmt.Print("Phone Number: ")
					fmt.Scanln(&phoneNumber)
				}
			}

			phoneNumber = normalizePhoneNumber(phoneNumber)
			if strings.HasPrefix(phoneNumber, "0") {
				phoneNumber = "98" + phoneNumber[1:]
			}

			c.Auth = c.cryptoHelper.Secret(32)
			c.Key = c.cryptoHelper.Passphrase(c.Auth)
			c.DecodeAuthStr = c.cryptoHelper.DecodeAuth(c.Auth)

			sendResult, err := c.SendCode(phoneNumber, "", "SMS")
			if err != nil {
				return fmt.Errorf("send code error: %w", err)
			}

			// Handle 2FA: keep asking for pass_key until OK
			for sendResult.GetString("status") == "SendPassKey" {
				hintPassKey := sendResult.GetString("hint_pass_key")
				fmt.Printf("Two-factor password [hint: %s] > ", hintPassKey)
				var passKey string
				fmt.Scanln(&passKey)
				sendResult, err = c.SendCode(phoneNumber, passKey, "SMS")
				if err != nil {
					c.logger.Printf("SendCode with passKey error: %v", err)
					continue
				}
			}

			publicKey, privateKey, err := c.cryptoHelper.CreateKeys()
			if err != nil {
				return fmt.Errorf("create keys error: %w", err)
			}
			c.PrivateKey = privateKey
			phoneCodeHash := sendResult.GetString("phone_code_hash")

			for {
				fmt.Print("Code: ")
				var phoneCode string
				fmt.Scanln(&phoneCode)

				signResult, err := c.SignIn(phoneCode, phoneNumber, phoneCodeHash, publicKey)
				if err != nil {
					c.logger.Printf("Sign in error: %v", err)
					continue
				}

				signStatus := signResult.GetString("status")
				if signStatus == "OK" {
					encAuth := signResult.GetString("auth")
					decAuth, err := c.cryptoHelper.DecryptRSAOAEP(c.PrivateKey, encAuth)
					if err != nil {
						return fmt.Errorf("decrypt auth error: %w", err)
					}

					c.Auth = decAuth
					c.Key = c.cryptoHelper.Passphrase(c.Auth)
					c.DecodeAuthStr = c.cryptoHelper.DecodeAuth(c.Auth)

					key, err := parsePrivateKey(c.PrivateKey)
					if err == nil {
						c.ImportKey = key
					}

					userUpdate := signResult.GetUpdate("user")
					userGUID := ""
					userPhone := ""
					if userUpdate != nil {
						userGUID = userUpdate.GetString("user_guid")
						userPhone = userUpdate.GetString("phone")
					}
					c.GUID = userGUID

					c.saveSession(c.Auth, userGUID, c.UserAgent, userPhone, c.PrivateKey)
					c.RegisterDevice(c.Name)
					c.logger.Printf("Registered successfully! GUID: %s", c.GUID)
					break
				}
			}
		} else {
			return fmt.Errorf("get user info error: %w", err)
		}
	} else {
		userUpdate := result.GetUpdate("user")
		if userUpdate != nil {
			c.GUID = userUpdate.GetString("user_guid")
		}
		c.logger.Printf("Logged in - User GUID: %s", c.GUID)
	}

	return nil
}

// saveSession persists session data according to SessionMode.
func (c *RubClient) saveSession(auth, guid, userAgent, phoneNumber, privateKey string) {
	if err := c.session.Insert(auth, guid, userAgent, phoneNumber, privateKey); err != nil {
		c.logger.Printf("Failed to save session: %v", err)
	}

	// Fire callback if in callback mode
	if c.SessionMode == SessionModeCallback && c.OnSessionSaved != nil {
		c.OnSessionSaved(SessionData{
			Auth:        auth,
			GUID:        guid,
			UserAgent:   userAgent,
			PhoneNumber: phoneNumber,
			PrivateKey:  privateKey,
		})
	}
}

func (c *RubClient) Run() {
	if c.connection == nil {
		c.logger.Println("Not connected. Call Connect() and Start() first.")
		return
	}
	c.connection.GetUpdates(c.stopCh)
}

func (c *RubClient) RunInBackground() {
	go c.Run()
}

func (c *RubClient) AddHandler(name string, fn func(*Update), filter func(map[string]interface{}) bool) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	c.handlers = append(c.handlers, Handler{
		Name:   capitalizeStr(name),
		Func:   fn,
		Filter: filter,
	})
}

func (c *RubClient) OnMessage(fn func(*Update)) {
	c.AddHandler("chat_updates", fn, func(_ map[string]interface{}) bool { return true })
}

func (c *RubClient) OnMessageMatch(pattern string, fn func(*Update)) {
	re := regexp.MustCompile(pattern)
	c.AddHandler("chat_updates", fn, func(data map[string]interface{}) bool {
		if msg, ok := data["message"].(map[string]interface{}); ok {
			if text, ok := msg["text"].(string); ok {
				return re.MatchString(text)
			}
		}
		return false
	})
}

func (c *RubClient) Disconnect() error {
	if c.connection == nil {
		return ErrNoConnection
	}
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	err := c.connection.Close()
	if c.session != nil {
		c.session.Close()
	}
	c.logger.Println("Client disconnected.")
	return err
}

func (c *RubClient) GetSessionString() (string, error) {
	ss := &StringSession{
		Auth:       c.Auth,
		GUID:       c.GUID,
		UserAgent:  c.UserAgent,
		PrivateKey: c.PrivateKey,
	}
	return ss.Encode()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

func capitalizeStr(text string) string {
	parts := strings.Split(text, "_")
	var result strings.Builder
	for _, part := range parts {
		if len(part) > 0 {
			result.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return result.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func splitText(text string, chunkSize int) []string {
	runes := []rune(text)
	if len(runes) <= chunkSize {
		return []string{text}
	}
	var chunks []string
	for i := 0; i < len(runes); i += chunkSize {
		end := i + chunkSize
		if end > len(runes) {
			end = len(runes)
		}
		chunks = append(chunks, string(runes[i:end]))
	}
	return chunks
}

func normalizePhoneNumber(phone string) string {
	phone = convertFarsiDigits(phone)
	phone = strings.TrimSpace(phone)
	for _, ch := range []string{" ", "-", "(", ")"} {
		phone = strings.ReplaceAll(phone, ch, "")
	}
	re := regexp.MustCompile(`^(?:\+|00)?(\d{7,15})$`)
	match := re.FindStringSubmatch(phone)
	if len(match) >= 2 {
		return match[1]
	}
	return phone
}

func convertFarsiDigits(text string) string {
	farsi := []rune("۰۱۲۳۴۵۶۷۸۹")
	result := []rune(text)
	for i, r := range result {
		for j, f := range farsi {
			if r == f {
				result[i] = rune('0' + j)
				break
			}
		}
	}
	return string(result)
}

func encodeUTF16(s string) []uint16 {
	return utf16.Encode([]rune(s))
}

func getMimeFromURL(urlStr string) string {
	resp, err := http.Head(urlStr)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		return ""
	}
	exts, err := mime.ExtensionsByType(contentType)
	if err != nil || len(exts) == 0 {
		return ""
	}
	return exts[0]
}
