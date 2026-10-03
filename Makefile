# FullTunnel Makefile

.PHONY: all build build-gui build-cli clean test tidy

all: build

build: build-gui build-cli

build-gui:
	go build -ldflags "-s -w" -o fulltunnel.exe main.go

build-cli:
	go build -ldflags "-s -w" -o fulltunnel-cli.exe ./cmd/cli/main.go

test:
	go test -v ./core/...

tidy:
	go mod tidy

clean:
	@if exist fulltunnel.exe del /f /q fulltunnel.exe
	@if exist fulltunnel-cli.exe del /f /q fulltunnel-cli.exe
	@if exist wintun.dll del /f /q wintun.dll
