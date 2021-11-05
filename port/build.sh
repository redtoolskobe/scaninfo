#!/usr/bin/env bash

echo "build macos x64 TxPortMap..."

CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o release/TxPortMap_macos_x64 cmd/TxPortMap/TxPortMap.go
echo "build windows x64 TxPortMap..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o release/TxPortMap_windows_x64.exe cmd/TxPortMap/TxPortMap.go
echo "build linux x64 TxPortMap..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o release/TxPortMap_linux_x64 cmd/TxPortMap/TxPortMap.go

