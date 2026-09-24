#!/bin/bash

# .env file content:
# GOOGLE_API_KEY="your-google-api-key"
#
# Place your sample at ./workdir/input.file before running.

source .env

docker build -f build/Dockerfile -t docker.io/attilamester/exelens .

docker run --rm \
    -e GOOGLE_API_KEY="${GOOGLE_API_KEY}" \
    -v "$(pwd)/workdir:/usr/exelens/workdir:rw" \
    "docker.io/attilamester/exelens"
