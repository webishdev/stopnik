#!/bin/bash

set -euo pipefail

ZIPPER=true
NICE_NAME=STOPnik
NAME=stopnik

OS_VALUES=(windows darwin linux)
ARCH_VALUES=(amd64 arm64)

LINUX_OS_VALUES=(linux windows)
MAC_OS_VALUES=(darwin)
WINDOWS_OS_VALUES=(windows)

function prepare() {
  if [[ "$#" -ne 1 ]]; then
    echo "Parameters for prepare are missing"
    echo
    exit 1
  fi

  if [[ $(git diff --stat) != '' ]]; then
    echo "Will ignore version settings and use 'dev', please commit current changes before build"
    echo
    VERSION=dev
  fi
  GIT_HASH=$(git rev-parse --short=11 HEAD)

  echo "$NAME $VERSION - $GIT_HASH"
  echo
  mkdir -p bin
}

function clean() {
  rm -rf bin
  echo "The bin/ directory was cleaned"
  echo
}

function build() {
  COGO_ENABLED=0
  FILE_EXTENSION=""
  if [[ "$GO_OS" == "windows" ]]; then
    FILE_EXTENSION=".exe"
  fi
  OS_NAME=$GO_OS
  if [[ "$GO_OS" == "darwin" ]]; then
      OS_NAME="macos"
  fi
  FILE_NAME="$NAME.$VERSION-$OS_NAME-$GO_ARCH"
  DIR="$OS_NAME-$GO_ARCH"
  echo "Build $NICE_NAME version $VERSION ($GIT_HASH) for $GO_OS $GO_ARCH into $DIR"
  GOOS=$GO_OS GOARCH=$GO_ARCH go build -ldflags="-s -w -X 'main.Version=$VERSION' -X 'main.GitHash=$GIT_HASH'" -o bin/$DIR/$FILE_NAME$FILE_EXTENSION main.go

  CURRENT_DIR=$(pwd)
  cd bin/$DIR

  if [[ "$GO_OS" == "darwin" ]]; then
    if command -v xattr &> /dev/null
    then
      type -a xattr
      echo "Removing extended attributes from $FILE_NAME$FILE_EXTENSION"
      ls -lah $FILE_NAME$FILE_EXTENSION
      file $FILE_NAME$FILE_EXTENSION
      xattr -rvx $FILE_NAME$FILE_EXTENSION
    fi
  fi

  echo "Create SHA256 sum for $GO_OS $GO_ARCH"
  shasum -a 256 $FILE_NAME$FILE_EXTENSION >> stopnik.${VERSION}-${OS_NAME}-${GO_ARCH}-sha256sum.txt
  if [[ "$ZIPPER" = true ]]; then
    ZIP_NAME="${NAME}.${VERSION}-${OS_NAME}-${GO_ARCH}.zip"
    echo "Package into ZIP: ${ZIP_NAME}"
    zip -q -r ../${ZIP_NAME} ./
  fi

  cd $CURRENT_DIR

  if [[ "$ZIPPER" = true ]]; then
    rm -rf bin/$DIR
  fi
  echo
}

function build_all() {
  for os_value in "${OS_VALUES[@]}"
  do
    for arch_value in "${ARCH_VALUES[@]}"
    do
      GO_OS=$os_value
      GO_ARCH=$arch_value
      build
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
  if [[ ! "$3" =~ ^v[0-9].[0-9]$|^ci$|^dev$ ]]; then
    echo "Wrong version format. Should be vX.Y, dev or ci"
    echo
    exit 1
  fi
  VERSION=$3
  echo "Building $NICE_NAME for OS $1 and platform $2"
  clean
  prepare $VERSION
  GO_OS=$1
  GO_ARCH=$2
  build
}

function task_build_ci() {
  if [[ "$#" -ne 2 ]]; then
    echo "No version, or GitHub OS argument supplied"
    echo
    exit 1
  fi
  VERSION=$1
  CI_OS=$2
  echo "Building $NICE_NAME version $VERSION on $CI_OS"
  clean
  prepare $VERSION
  if [[ "$CI_OS" == "ubuntu-latest" ]]; then
    CURRENT_OS_VALUES=( "${LINUX_OS_VALUES[@]}" )
  elif [[ "$CI_OS" == "macos-latest" ]]; then
    CURRENT_OS_VALUES=( "${MAC_OS_VALUES[@]}" )
  elif [[ "$CI_OS" == "windows-latest" ]]; then
    CURRENT_OS_VALUES=( "${WINDOWS_OS_VALUES[@]}" )
  fi
  for os_value in "${CURRENT_OS_VALUES[@]}"
  do
    for arch_value in "${ARCH_VALUES[@]}"
    do
      GO_OS=$os_value
      GO_ARCH=$arch_value
      build
    done
  done
}

function task_build_all() {
  if [[ "$#" -ne 1 ]]; then
    echo "No version argument supplied"
    echo
    exit 1
  fi
  if [[ ! "$1" =~ ^v[0-9].[0-9]$|^ci$|^dev$ ]]; then
    echo "Wrong version format. Should be vX.Y, dev or ci"
    echo
    exit 1
  fi
  VERSION=$1
  echo "Building $NICE_NAME for all platforms"
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

    build_ci version github_os

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
  build_ci) task_build_ci "$@";;
  build_all) task_build_all "$@";;
  *) task_usage ;;
esac
