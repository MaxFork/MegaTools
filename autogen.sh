#! /bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

ORIGDIR=`pwd`
cd $srcdir

mkdir -p m4

autoreconf -v --install || exit 1
cd $ORIGDIR || exit $?

$srcdir/configure --enable-maintainer-mode --enable-warnings "$@"

cat << EOF
=========================================================================
|           WARNING         You're building from GIT code               |
=========================================================================
| - Don't! git is for developers, release tarballs are for end users.   |
|   Get them here:  https://megatools.megous.com/builds/                |
| - Read the README for build instructions!                             |
| - Random checkouts from git are not tested.                           |
=========================================================================
EOF