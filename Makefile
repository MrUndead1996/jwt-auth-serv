.PHONY: build
build:
	go build -v ./cmd/authServer/main/
.DEFAULT_GOAL := build