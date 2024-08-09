#!/bin/sh

bindir="$1"

mkdir -p "${DESTDIR}/${MESON_INSTALL_PREFIX}/$bindir"

for cmd in df dl get ls test export mkdir put reg rm copy
do
  ln -snf megatools "${DESTDIR}/${MESON_INSTALL_PREFIX}/$bindir/mega$cmd"
done
