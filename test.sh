#!/bin/bash


COVERAGE_DIR=test_coverage

function clean() {
    echo "Clean up"
    rm -rf $COVERAGE_DIR
}

function prepare() {
  mkdir -p $COVERAGE_DIR

  echo "Run tests"
  go test ./... -coverprofile $COVERAGE_DIR/coverage.out -covermode count
}

function html() {
  echo "Create Coverage HTML"
  go tool cover -html=$COVERAGE_DIR/coverage.out -o $COVERAGE_DIR/test-coverage.html
}

function coverage() {
  echo "Show Coverage"
  go tool cover -func=$COVERAGE_DIR/coverage.out
}

function task_clean() {
  clean
}

function task_html() {
  clean
  prepare
  html
}

function task_default() {
  clean
  prepare
  coverage
}

function task_usage() {
  cat <<HEREDOC
usage: $0 <command>
Available commands:

    clean
       Cleans the coverage directory

    html
       Test + HTML Report

    coverage
        Test + Coverage

HEREDOC
  exit 1
}

cmd="${1:-}"
shift || true
case "$cmd" in
  clean) task_clean "$@";;
  html) task_html "$@";;
  coverage) task_default ;;
  *) task_usage ;;
esac