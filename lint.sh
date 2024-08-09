#!/bin/bash

set -euo pipefail

if ! command -v golangci-lint &> /dev/null
then
    echo "golangci-lint could not be found"
    exit 1
fi

golangci-lint run