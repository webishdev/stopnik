#!/bin/bash

./build.sh build_all dev

mkdir dist
cp -f bin/stopnik.dev-linux-arm64.zip dist/
cd dist
unzip stopnik.dev-linux-arm64.zip