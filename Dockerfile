FROM golang:1.26-bookworm AS build
WORKDIR /project
COPY server/ ./server/
COPY scripts/fetch_rubingo_source.sh ./scripts/fetch_rubingo_source.sh
# Fetch exact MIT-licensed Go library revision. No previous APK is used.
RUN bash scripts/fetch_rubingo_source.sh
WORKDIR /project/server
RUN go mod tidy && go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/rubika-saf-backend .
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /data && chmod 0700 /data
WORKDIR /app
COPY --from=build /out/rubika-saf-backend /app/rubika-saf-backend
ENV PORT=8080
ENV QUEUE_DATA_DIR=/data
EXPOSE 8080
CMD ["/app/rubika-saf-backend"]
