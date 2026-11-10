FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY . .
RUN test -s rubingo/rubingo.go && go mod tidy && CGO_ENABLED=0 go build -trimpath -o /out/rubika-saf .
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/rubika-saf /app/rubika-saf
ENV PORT=8080
EXPOSE 8080
CMD ["/app/rubika-saf"]
