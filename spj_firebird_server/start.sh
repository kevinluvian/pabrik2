#!/bin/bash

cp /usr/lib64/libfbclient.so.2 /usr/lib/libfbclient.so.2


# Start the Firebird service in the background
echo "Starting Firebird service..."
/etc/init.d/firebird start

/opt/firebird/bin/fbguard -forever &
wait $!
