#!/bin/bash

set -euo pipefail

echo "Cleaning workspace"

rm -rf bin/
rm -rf dist/
rm -rf .test_coverage/
rm -rf .run/
rm -rf .lint_result/
rm -f stopnik