#!/bin/sh

while :; do
  /sbin/start-stop-daemon -S -b -x /sbin/umtsd
  sleep 5
done
