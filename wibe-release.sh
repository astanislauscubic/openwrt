#!/bin/bash

RELDIR=../releases/$1
mkdir -p $RELDIR

cp bin/ramips/openwrt-ramips-rt305x-wibe-4g-8M-squashfs-sysupgrade.bin $RELDIR/wibe-4g-8M-$1.bin
cp wibe-readme $RELDIR/ReleaseNotes.txt
if [[ "$V" == *"rc"* ]]; then
  cp wibe-readme-internal $RELDIR/ReleaseNotes.txt
fi
cp build_dir/target*/net-snmp-5.7.3/mibs/WIBE-MIB.txt $RELDIR/WIBE-MIB.txt
pushd $RELDIR
unix2dos ReleaseNotes.txt
zip ../wibe-$1.zip *
popd
