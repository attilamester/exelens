#!/bin/bash

# .env file content:
# FILE_PATH="/absolute/path/to/your/sample/on/host/system"

source .env

docker run --rm \
    -e GOOGLE_API_KEY="${GOOGLE_API_KEY}" \
    -v "${FILE_PATH}:/usr/exelens/workdir/input.file:ro" \
    -v "./workdir:/usr/exelens/workdir:rw" \
    "docker.io/attilamester/exelens"
