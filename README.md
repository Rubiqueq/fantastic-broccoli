# Rubika SAF v1.0.0 — new APK from Internet source

This repository contains a new Java Android client and the actual downloaded MIT-licensed [Rubingo](https://github.com/farshadnobody/Rubingo) Rubika client source code (Go), pinned to upstream Git commit `39f780813e558f390a9404964e1d9ec80748e66f`.

**NO binary, APK, Android source, Java source, server code, or package ID was copied from the old THREE IB project.** GitHub Actions compiles this new app independently.

## Android
Android APK has a distinct package `com.rubiqueq.saf`, v1.0.0, builds with Android SDK 35, Gradle 8.9 and JDK 17. Open the app, enter the dedicated Railway HTTPS backend address and API key, then request an OTP and sign in. Choose a CSV/XLSX file with `phone,opt_in,opt_in_source,message` fields, and press START to queue only explicitly opted-in rows. Messages require the server to resolve the phone to a Rubika user GUID. STOP cancels future attempts. The local queue index is persisted; unresolved or uncertain attempts stop the queue to avoid repeat sends.

## Server
The Go server imports the downloaded original Rubingo library stored at `server/rubingo/rubingo.go` with the original MIT license at `server/RUBINGO_LICENSE.txt`. The HTTP API supports `/health`, `/status`, `/login/send-code`, `/login/verify` and `/send-text`. To run: set `API_KEY` to a random secret (minimum 24 characters), then run `go run .` from `server`, or deploy the repository Dockerfile on Railway and set `API_KEY` as a secret variable.

**Limitations:** This is a debug-signed preview. Personal-account OTP, provider phone-to-GUID resolution, 2FA edge cases, image sending and live delivery are not verified. Sending is limited to consented rows. In-memory sessions and background app threads are not sufficient for a production guaranteed-uptime queue. Real live testing and session persistence will be required before production use. API keys and OTPs are never included in Git.

## Open source credits
Rubingo by FARSHAD nobody (2026), MIT license; upstream commit `39f780813e558f390a9404964e1d9ec80748e66f` (see `server/RUBINGO_LICENSE.txt`).
