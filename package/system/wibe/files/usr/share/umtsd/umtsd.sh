#!/bin/sh

. /etc/openwrt_release
export DISTRIB_DESCRIPTION

while :; do
  /sbin/start-stop-daemon -S -b -x /sbin/umtsd
  sleep 5
done
