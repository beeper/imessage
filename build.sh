#!/bin/bash
set -xe
build_tags=""

commit=${COMMIT_HASH:-$(git rev-parse HEAD)}

if [[ $(arch) == "arm64" && -z "$LIBRARY_PATH" && -d /opt/homebrew ]]; then
	echo "Using /opt/homebrew for LIBRARY_PATH and CPATH"
	export LIBRARY_PATH=/opt/homebrew/lib
	export CPATH=/opt/homebrew/include
	HEIF_PATH="$LIBRARY_PATH"
else
	HEIF_PATH="/usr/local/lib"
fi

if [[ -f "$HEIF_PATH/libheif.1.dylib" ]]; then
	echo "libheif found in $HEIF_PATH, compiling with heif support"
	build_tags="libheif"
else
	echo "libheif not found in $HEIF_PATH, compiling without heif support"
fi

go build -o beeper-imessage -tags "$build_tags" -ldflags "-X main.Commit=$commit -X 'main.BuildTime=`date '+%b %_d %Y, %H:%M:%S'`'"
