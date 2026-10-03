# SecureTunnel Makefile

.PHONY: all build build-gui build-cli clean test tidy

all: build

build: build-gui build-cli

build-gui:
	go build -ldflags "-s -w" -o securetunnel.exe main.go

build-cli:
	go build -ldflags "-s -w" -o securetunnel-cli.exe ./cmd/cli/main.go

test:
	go test -v ./core/...

tidy:
	go mod tidy

clean:
	@if exist securetunnel.exe del /f /q securetunnel.exe
	@if exist securetunnel-cli.exe del /f /q securetunnel-cli.exe
	@if exist wintun.dll del /f /q wintun.dll
