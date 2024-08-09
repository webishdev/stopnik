#!/bin/bash

set -euo pipefail

echo "Will test with https://golangci-lint.run/"
echo

if ! command -v golangci-lint &> /dev/null
then
    echo "golangci-lint could not be found"
    exit 1
fi

rm -rf .lint_result/

golangci-lint run