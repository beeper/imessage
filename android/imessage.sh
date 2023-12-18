#!/bin/bash

set -e

ANDROID_API=26
NDK_VERSION=24.0.8215888
ROOT="$(cd "$(dirname "$0")"; pwd)"

if [ -z "$ANDROID_HOME" ]; then
	echo "ANDROID_HOME not set"
	exit 1
fi

NDK_ROOT="$ANDROID_HOME/ndk/$NDK_VERSION"
if [ ! -d "$NDK_ROOT" ]; then
	echo "Missing Android NDK"
	exit 1
fi

if [ "$(uname)" = 'Darwin' ]; then
  NDK_ARCH="darwin-x86_64"
else
  NDK_ARCH="linux-x86_64"
fi

LDFLAGS="-s -w -X main.Tag=$(git describe --exact-match --tags 2>/dev/null) -X main.Commit=$(git rev-parse HEAD) -X 'main.BuildTime=$(date '+%b %_d %Y, %H:%M:%S')'"

build_imessage() {
  local ANDROID_ARCH=$1
  local NDK_TARGET=$2
  local GOARCH=$3
  local GOARM=$4
  local LIB_JNI="$ROOT/library/src/main/jniLibs/$ANDROID_ARCH"
  echo
  echo "Building $ANDROID_ARCH"
  echo

  rm -rf "$LIB_JNI"
  mkdir -p "$LIB_JNI"

  (set -x; CGO_LDFLAGS="-lm -llog" CGO_ENABLED=1 GOOS=android GOARCH=$GOARCH GOARM=$GOARM \
  CC="$NDK_ROOT/toolchains/llvm/prebuilt/$NDK_ARCH/bin/$NDK_TARGET$ANDROID_API-clang" \
  go build -ldflags "$LDFLAGS" -o "$LIB_JNI"/libima.so ./imessage/ffi)
}

build_imessage armeabi-v7a armv7a-linux-androideabi arm 7
build_imessage arm64-v8a aarch64-linux-android arm64
build_imessage x86 i686-linux-android 386
build_imessage x86_64 x86_64-linux-android amd64
