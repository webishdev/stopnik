#!/bin/bash


COVERAGE_DIR=test_coverage

echo "Clean up"
rm -rf $COVERAGE_DIR
mkdir -p $COVERAGE_DIR

echo "Run tests"
go test ./... -coverprofile $COVERAGE_DIR/coverage.out -covermode count

echo "Create Coverage HTML"
go tool cover -html=$COVERAGE_DIR/coverage.out -o $COVERAGE_DIR/test-coverage.html
