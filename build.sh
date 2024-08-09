#!/bin/sh



# Check if inotifywait is installed
#if [ -z "$(which inotifywait)" ]; then
if ! command -v inotifywait ^> /dev/null; then
    echo "inotifywait is not installed."
    echo "Install the inotify-tools package and try again."
    exit 1
fi

FIRST_BUILD=0
if [ ! -f configure ]; then
    FIRST_BUILD=1
fi

BUILD_SYSTEM=ninja
if ! command -v ninja ^> /dev/null; then
    echo "WARNING: The ninja build system is not installed."
    echo "         Consider installing it for a much better experience."
    echo

    BUILD_SYSTEM=make
fi

function buildViaMake() {
    if [ ! -f ./Makefile.in ]; then
        ./autogen.sh
    fi

    rm -f megatools

    make -j4

    echo "All builds completed!"
}

function build() {
    if [ "${BUILD_SYSTEM}" = "make" ]; then
        buildViaMake
    else
        ninja
    fi
}

build

if [ $FIRST_BUILD -eq 1 ]; then
    exit
fi

# If Makefile.am is changed, rebuild the Makefiles...
(inotifywait -e close_write -m ./Makefile.am | while read; do
    echo "Changed Makefile.am.."
    ./autogen.sh
    buildViaMake
done) &
WATCH1_PID=$!


## Watch for changes to .cs files in the directory and subdirectories
inotifywait --recursive --monitor --format "%e %w%f" \
    --event close_write,build.ninja $dir \
    --include '\.c$' |
    while read changed; do
        echo "Detected change in $changed"
        build
    done

wait $WATCH1_PID