#!/bin/bash

cp /usr/lib64/libfbclient.so.2 /usr/lib/libfbclient.so.2

/opt/firebird/bin/fbguard -forever &

# Start the Firebird service in the background
echo "Starting Firebird service..."
/etc/init.d/firebird start

# Run the Python script with Prometheus metrics
echo "Starting Python application..."
exec python3 main.py
