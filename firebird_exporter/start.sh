#!/bin/bash

# Start the Firebird service in the background
echo "Starting Firebird service..."
/etc/init.d/firebird start

# Run the Python script with Prometheus metrics
echo "Starting Python application..."
exec python3 main.py