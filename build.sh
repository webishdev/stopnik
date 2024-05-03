#!/bin/bash

set -euo pipefail

NICE_NAME=STOPnik
NAME=stopnik

OS_VALUES=(windows darwin linux)
ARCH_VALUES=(amd64 arm64)

function prepare() {
  if [[ "$#" -ne 1 ]]; then
    echo "Parameters for prepare are missing"
    echo
    exit 1
  fi

  if [[ $(git diff --stat) != '' ]]; then
    echo "Please commit current changes before build"
    echo
    exit 1
  else
    VERSION=$1
    GIT_HASH=$(git rev-parse --short=11 HEAD)

    echo "$VERSION" > resources/version
    echo "$GIT_HASH" >> resources/version

    echo "$NAME $VERSION - $GIT_HASH"
    echo
  fi
  mkdir -p bin
}

function clean() {
  rm -rf bin
  echo "The bin/ directory was cleaned"
  echo
}

function build() {
  if [[ "$#" -ne 3 ]]; then
    echo "Parameters for build are missing"
    echo
    exit 1
  fi
  VERSION=$1
  GO_OS=$2
  GO_ARCH=$3
  COGO_ENABLED=0
  FILE_EXTENSION=""
  if [[ "$GO_OS" == "windows" ]]; then
    FILE_EXTENSION=".exe"
  fi
  OS_NAME=$GO_OS
  if [[ "$GO_OS" == "darwin" ]]; then
      OS_NAME="macos"
    fi
  FILE_NAME="$NAME$VERSION-$GO_ARCH"
  DIR="$OS_NAME-$GO_ARCH"
  echo "Build $NICE_NAME version $VERSION for $GO_OS $GO_ARCH"
  GOOS=$GO_OS GOARCH=$GO_ARCH go build -ldflags="-s -w" -o bin/$DIR/$FILE_NAME$FILE_EXTENSION
  echo "Create SHA256 Sum $GO_OS $GO_ARCH"
  sha256sum bin/$DIR/$FILE_NAME$FILE_EXTENSION >> bin/$DIR/sha256sum.txt
  CURRENT_DIR=$(pwd)
  echo "Package"
  cd bin/$DIR
  zip -q -r ../${NAME}${VERSION}-${OS_NAME}-${GO_ARCH}.zip ./
  cd $CURRENT_DIR
  echo
}

function build_all() {
  if [[ "$#" -ne 1 ]]; then
      echo "Parameters for build_all are missing"
      echo
      exit 1
    fi
  for os_value in "${OS_VALUES[@]}"
  do
    for arch_value in "${ARCH_VALUES[@]}"
    do
      build $1 $os_value $arch_value
    done
  done
  echo "Done!"
}

function task_clean() {
    clean
}

function task_build() {
  if [[ "$#" -ne 1 ]]; then
    echo "No version argument supplied"
    echo
    exit 1
  fi
  if [[ ! "$1" =~ ^[0-9].[0-9]$ ]]; then
    echo "Wrong version format. Should be x.y"
    echo
    exit 1
  fi
  echo "Building $NICE_NAME version $1"
  clean
  prepare $1
  build_all $1
}

function task_usage() {
  cat <<HEREDOC
usage: $0 <command>
Available commands:

    clean
       Cleans the bin directory

    build version
        Builds the current version of $NICE_NAME

HEREDOC
  exit 1
}

cmd="${1:-}"
shift || true
case "$cmd" in
  clean) task_clean "$@";;
  build) task_build "$@";;
  *) task_usage ;;
esac
