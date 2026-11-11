# Rubika SAF 1.2.0 RC2 - Acceptance matrix

| Check | State | Evidence |
| --- | --- | --- |
| Go scheduler tests and race detector | PASS (local) | 15 scheduler tests, `GO111MODULE=off GODEBUG=httpmuxgo121=0 go test -race ./scheduler` |
| Go server integration tests | PASS against OFFLINE fake Rubingo | Two HTTP tests including 401, 409, 415, atomic media upload and 0600 permission |
| Go backend compilation | PASS against OFFLINE fake Rubingo | `go build`, `go vet` |
| Java app syntax/type checking | PASS against local Android stubs only | `javac --release 17` |
| Imported 999-row Excel | PASS offline | 999 unique normalized numbers; 0 opted-in rows |
| Imported 999-row CSV | PASS offline | 999 unique normalized numbers; 0 opted-in rows |
| Server compiles with actual Rubingo dependency | NOT TESTED | Needs CI network and pinned source download |
| Fresh Android SDK 35 Gradle APK build | NOT TESTED | SDK/Gradle unavailable in current container |
| APK signature and installed package | NOT TESTED | No RC2 APK yet |
| Personal Rubika OTP login (real) | NOT TESTED | Requires account owner entering OTP |
| Real text, image, GUID resolution, delivery | NOT TESTED | Needs authorized recipient and provider verification |
| Server persistent volume and restart | NOT CONFIGURED/TESTED | Mount Railway volume `/data` |
| Stable release signing | NOT CONFIGURED | Debug signing is for development only |
| API key rotation / security | REQUIRED | Prior API key appeared in conversation |
