#!/bin/bash

cp /usr/lib64/libfbclient.so.2 /usr/lib/libfbclient.so.2

/opt/firebird/bin/fbguard -forever &
FB_PID=$!

# Start the Firebird service in the background
echo "Starting Firebird service..."
/etc/init.d/firebird start

wait $FB_PID
