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
  Phone string `json:"phone"`
  Password string `json:"password"`
  Code string `json:"code"`
  Text string `json:"text"`
  RecipientGUID string `json:"recipient_guid"`
  OptIn bool `json:"opt_in"`
}

var app struct {
  sync.Mutex
  client *rubingo.RubClient
  challenge *rubingo.SendCodeResult
  account string
  authenticated bool
  lastSent time.Time
}

var phoneFormat=regexp.MustCompile(`^989[0-9]{9}$`)
var guidFormat=regexp.MustCompile(`^u0[A-Za-z0-9]{1,126}$`)

func normalizePhone(s string) string {
  s=strings.NewReplacer(" ","","-","","+","").Replace(strings.TrimSpace(s))
  if strings.HasPrefix(s,"09"){s="98"+s[1:]}
  if strings.HasPrefix(s,"9")&&len(s)==10{s="98"+s}
  return s
}

func reply(w http.ResponseWriter,code int,v interface{}){
  w.Header().Set("Content-Type","application/json; charset=utf-8")
  w.Header().Set("Cache-Control","no-store")
  w.WriteHeader(code)
  _=json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, code int, why string){reply(w,code,map[string]string{"error":why})}
func authorized(r *http.Request) bool {
  key:=os.Getenv("API_KEY")
  header:=r.Header.Get("X-API-Key")
  return len(key)>=24&&len(header)==len(key)&&subtle.ConstantTimeCompare([]byte(header),[]byte(key))==1
}
func data(r *http.Request)(request,error) {
  var v request
  if r.Method!=http.MethodPost{return v,errors.New("POST only")}
  r.Body=http.MaxBytesReader(nil,r.Body,16384)
  if err:=json.NewDecoder(r.Body).Decode(&v);err!=nil{return v,err}
  return v,nil
}
func locateGUID(x interface{})string {
  switch obj:=x.(type){
  case map[string]interface{}:
    for k,v:=range obj {
      if strings.EqualFold(k,"user_guid") || strings.EqualFold(k,"object_guid"){
        if s,ok:=v.(string);ok&&guidFormat.MatchString(s){return s}
      }
    }
    for _,v:=range obj {if s:=locateGUID(v);s!=""{return s}}
  case []interface{}:
    for _,v:=range obj {if s:=locateGUID(v);s!=""{return s}}
  }
  return ""
}
func main(){
  if len(os.Getenv("API_KEY"))<24{log.Fatal("API_KEY must be set to at least 24 chars")}
  mux:=http.NewServeMux()
  mux.HandleFunc("/health",func(w http.ResponseWriter,r *http.Request){
    if r.Method!=http.MethodGet{fail(w,405,"GET only");return}
    reply(w,200,map[string]interface{}{"ok":true,"backend":"Rubingo/MIT","personal_login_verified":false})
  })
  mux.HandleFunc("/status",func(w http.ResponseWriter,r *http.Request){
    if !authorized(r){fail(w,401,"unauthorized");return}
    app.Lock();defer app.Unlock()
    reply(w,200,map[string]interface{}{"authenticated":app.authenticated})
  })
  mux.HandleFunc("/login/send-code",func(w http.ResponseWriter,r *http.Request){
    if !authorized(r){fail(w,401,"unauthorized");return}
    q,err:=data(r);if err!=nil{fail(w,400,"invalid_json");return}
    p:=normalizePhone(q.Phone);if !phoneFormat.MatchString(p){fail(w,400,"invalid_phone");return}
    app.Lock();defer app.Unlock()
    if app.client!=nil{app.client.Disconnect()}
    client,err:=rubingo.NewClient("rubika_saf",rubingo.WithSessionCallback(func(rubingo.SessionData){}))
    if err!=nil{fail(w,502,"client_init_failed");return}
    if err=client.Connect();err!=nil{fail(w,502,"connect_failed");return}
    challenge,err:=client.SendCodeExt(p,q.Password)
    if err!=nil{
      client.Disconnect()
      fail(w,502,fmt.Sprintf("login_challenge_failed: %s",err.Error()));return
    }
    if challenge==nil||challenge.PhoneCodeHash==""||challenge.TmpSession==""{client.Disconnect();fail(w,502,"login_challenge_incomplete");return}
    app.client=client;app.challenge=challenge;app.account=p;app.authenticated=false
    reply(w,200,map[string]string{"status":"OTP_REQUESTED"})
  })
  mux.HandleFunc("/login/verify",func(w http.ResponseWriter,r *http.Request){
    if !authorized(r){fail(w,401,"unauthorized");return}
    q,err:=data(r);if err!=nil{fail(w,400,"invalid_json");return}
    if len(q.Code)<4||len(q.Code)>12{fail(w,400,"invalid_code");return}
    app.Lock();defer app.Unlock()
    if app.client==nil||app.challenge==nil{fail(w,409,"request_code_first");return}
    result,err:=app.client.SignInExt(q.Code,app.account,app.challenge.PhoneCodeHash,app.challenge.TmpSession)
    if err!=nil{fail(w,502,"signin_failed: "+err.Error());return}
    if _,err=app.client.ApplySignInResult(result);err!=nil{fail(w,502,"session_apply_failed");return}
    app.authenticated=true;app.challenge=nil
    reply(w,200,map[string]string{"status":"AUTHENTICATED"})
  })
  mux.HandleFunc("/send-text",func(w http.ResponseWriter,r *http.Request){
    if !authorized(r){fail(w,401,"unauthorized");return}
    q,err:=data(r);if err!=nil{fail(w,400,"invalid_json");return}
    if !q.OptIn{fail(w,403,"recipient_opt_in_required");return}
    if len(strings.TrimSpace(q.Text))==0||len([]rune(q.Text))>4200{fail(w,400,"invalid_message_length");return}
    app.Lock();defer app.Unlock()
    if !app.authenticated||app.client==nil{fail(w,401,"login_required");return}
    if time.Since(app.lastSent)<30*time.Second{fail(w,429,"minimum_30_second_interval");return}
    guid:=strings.TrimSpace(q.RecipientGUID)
    if guid=="" {
      p:=normalizePhone(q.Phone)
      if !phoneFormat.MatchString(p){fail(w,400,"invalid_phone");return}
      lookup,lookupErr:=app.client.Builder("addAddressBook",false,true,map[string]interface{}{"phone":p,"first_name":"Rubika SAF"})
      if lookupErr!=nil{fail(w,422,"recipient_lookup_failed");return}
      guid=locateGUID(lookup.Data)
    }
    if !guidFormat.MatchString(guid){fail(w,422,"recipient_guid_unresolved");return}
    result,err:=app.client.SendMessage(rubingo.SendMessageOptions{ObjectGUID:guid,Text:q.Text})
    if err!=nil{fail(w,502,"send_failed: "+err.Error());return}
    id:=strings.TrimSpace(result.MessageID())
    if id==""{fail(w,502,"message_id_missing_check_delivery_before_retry");return}
    app.lastSent=time.Now()
    reply(w,200,map[string]string{"status":"submitted","message_id":id})
  })
  port:=os.Getenv("PORT");if port==""{port="8080"}
  srv:=&http.Server{Addr:":"+port,Handler:mux,ReadHeaderTimeout:10*time.Second}
  log.Printf("Rubika SAF API listening on %s; never log auth/otp",port)
  log.Fatal(srv.ListenAndServe())
}
