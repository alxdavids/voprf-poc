#!/bin/bash

set -x  # optional

devbase=$HOME/work/oprf-poc/go
port=6060

docker run \
    --rm \
    -e "GOPATH=/tmp/go" \
    -p 127.0.0.1:$port:$port \
    -v $devbase:/tmp/go/src/ \
    --name godoc \
    golang \
    bash -c "go get golang.org/x/tools/cmd/godoc && echo http://localhost:$port/pkg/ && /tmp/go/bin/godoc -http=:$port"