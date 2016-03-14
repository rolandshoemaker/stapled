#!/bin/bash
pkgs=$(go list -f '{{ .ImportPath }}' ./... | grep -v vendor)
for pkg in ${pkgs}; do
    go test -race -cover ${pkg}
done
