#!/usr/bin/env bash

# Compile the log-to-gor program
go build -o log-to-gor

# Run the log-to-gor program
./log-to-gor test.log requests.gor

grep '1759409411000000000' requests.gor

if [ $? -ne 0 ]; then
    echo "FATAL: requests.gor has changed"
    exit 1
else
    echo "No changes"
fi

