package main

import (
	"os"
	"testing"
)

func Test_Version(t *testing.T) {
	oldStdout := os.Stdout

	tempFile, tempFileError := os.CreateTemp("", "help_test.tmp")
	if tempFileError != nil {
		t.Fatal(tempFileError)
	}

	os.Stdout = tempFile
	printVersion("foo", "bar")

	os.Stdout = oldStdout
}

func Test_Help(t *testing.T) {
	oldStdout := os.Stdout

	tempFile, tempFileError := os.CreateTemp("", "help_test.tmp")
	if tempFileError != nil {
		t.Fatal(tempFileError)
	}

	os.Stdout = tempFile
	printHelp("foo", "bar")

	os.Stdout = oldStdout
}
