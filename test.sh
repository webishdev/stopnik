#!/bin/bash

echo "Run tests"
go test ./... -coverprofile=coverage.out

echo "Create Coverage HTML"
go tool cover -html=coverage.out