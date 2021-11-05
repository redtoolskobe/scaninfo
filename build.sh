#!/usr/bin/env bash

echo "build macos x64 scaninfo..."

CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o release/scaninfo_macos cmd/main.go
echo "build windows x64 scaninfo..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o release/scaninfo_windows_x64.exe cmd/main.go
echo "build linux x64 scaninfo..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o release/scaninfo_linux_x64 cmd/main.go

