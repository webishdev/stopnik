#!/bin/bash

NAME=stopnik
VERSION=0.1
OS_VALUES=(windows darwin linux)
ARCH_VALUES=(amd64 arm64)

function prepare() {
  if [[ $(git diff --stat) != '' ]]; then
    echo "Please commit current changes before build"
    echo
    exit 1
  else
    GIT_HASH=$(git rev-parse --short=11 HEAD)

    echo "$VERSION" > resources/version
    echo "$GIT_HASH" >> resources/version

    echo "$NAME $VERSION - $GIT_HASH"
    echo
  fi
  mkdir -p bin
}

function clean() {
  echo "Clean up"
  rm -rf bin
}

function build() {
  GO_OS=$1
  GO_ARCH=$2
  COGO_ENABLED=0
  FILE_EXTENSION=""
  if [[ "$GO_OS" == "windows" ]]; then
    FILE_EXTENSION=".exe"
  fi
  OS_NAME=$GO_OS
  if [[ "$GO_OS" == "darwin" ]]; then
      OS_NAME="macos"
    fi
  FILE_NAME="$NAME-$GO_ARCH"
  DIR="$OS_NAME-$GO_ARCH"
  echo "Build $GO_OS $GO_ARCH"
  GOOS=$GO_OS GOARCH=$GO_ARCH go build -ldflags="-s -w" -o bin/$DIR/$FILE_NAME$FILE_EXTENSION
  echo "Create SHA256 Sum $GO_OS $GO_ARCH"
  sha256sum bin/$DIR/$FILE_NAME$FILE_EXTENSION >> bin/$DIR/sha256sum.txt
  CURRENT_DIR=$(pwd)
  echo "Package"
  cd bin/$DIR
  zip -q -r ../${NAME}-${OS_NAME}-${GO_ARCH}.zip ./
  cd $CURRENT_DIR
  echo
}

function build_all() {
    for os_value in "${OS_VALUES[@]}"
    do
      for arch_value in "${ARCH_VALUES[@]}"
      do
    	  build $os_value $arch_value
      done
    done

}

clean
prepare
build_all

echo "Done!"
