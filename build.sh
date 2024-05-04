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
    GIT_HASH=$(git rev-parse --short=11 HEAD)

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
  if [[ "$#" -ne 2 ]]; then
    echo "Parameters for build are missing"
    echo
    exit 1
  fi
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
  FILE_NAME="$NAME$VERSION-$GO_ARCH"
  DIR="$OS_NAME-$GO_ARCH"
  echo "Build $NICE_NAME version $VERSION ($GIT_HASH) for $GO_OS $GO_ARCH"
  GOOS=$GO_OS GOARCH=$GO_ARCH go build -ldflags="-s -w -X 'main.Version=$VERSION' -X 'main.GitHash=$GIT_HASH'" -o bin/$DIR/$FILE_NAME$FILE_EXTENSION
  echo "Create SHA256 sum for $GO_OS $GO_ARCH"
  sha256sum bin/$DIR/$FILE_NAME$FILE_EXTENSION >> bin/$DIR/sha256sum.txt
  CURRENT_DIR=$(pwd)
  echo "Package into Zip"
  cd bin/$DIR
  zip -q -r ../${NAME}${VERSION}-${OS_NAME}-${GO_ARCH}.zip ./
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
  echo "Build done!"
}

function task_clean() {
    clean
}

function task_build() {
  if [[ "$#" -ne 3 ]]; then
    echo "No OS, arch or version argument supplied"
    echo
    exit 1
  fi
  if [[ ! "$1" =~ ^windows$|^linux$|^darwin$ ]]; then
    echo "Wrong os format. Should be windows, linux or darwin"
    echo
    exit 1
  fi
  if [[ ! "$2" =~ ^amd64$|^arm64$ ]]; then
    echo "Wrong os format. Should be amd64 or arm64"
    echo
    exit 1
  fi
  if [[ ! "$3" =~ ^[0-9].[0-9]$|^ci$ ]]; then
    echo "Wrong version format. Should be x.y or ci"
    echo
    exit 1
  fi
  SELECTED_OS=$1
  SELECTED_ARCH=$2
  VERSION=$3
  echo "Building $NICE_NAME version $VERSION"
  clean
  prepare $VERSION
  build $SELECTED_OS $SELECTED_ARCH
}

function task_build_all() {
  if [[ "$#" -ne 1 ]]; then
    echo "No version argument supplied"
    echo
    exit 1
  fi
  if [[ ! "$1" =~ ^[0-9].[0-9]$|^ci$ ]]; then
    echo "Wrong version format. Should be x.y or ci"
    echo
    exit 1
  fi
  VERSION=$1
  echo "Building $NICE_NAME version $VERSION"
  clean
  prepare $VERSION
  build_all
}

function task_usage() {
  cat <<HEREDOC
usage: $0 <command>
Available commands:

    clean
       Cleans the bin directory

    build os arch version

    build_all version
        Builds the current version of $NICE_NAME

HEREDOC
  exit 1
}

cmd="${1:-}"
shift || true
case "$cmd" in
  clean) task_clean "$@";;
  build) task_build "$@";;
  build_all) task_build_all "$@";;
  *) task_usage ;;
esac
