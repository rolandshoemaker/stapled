#!/bin/bash

# boostrap-dev.sh is run as the `vagrant` user by Vagrant (see Vagrantfile) during
# provisioning. It is the non-root half of bootstrap-dev-admin.sh
#
# To make it convenient to develop on the host machine the `/vagrant` mount
# shared between the host and the Vagrant VM is linked directly into the Gopath
# on the VM. Edit locally, `vagrant ssh`, `cd` to the src directory in `~/workspace`,
# and run `go test ./...` to test local work.
#
# Responsibilities:
#   - Creating a $GOPATH
#   - Adding $GOPATH to the environment
#   - Adding $GOPATH's bin/ to the $PATH
#   - Linking the Vagrant host's mountpoint into the $GOPATH
#   - Installing godep
#   - Vetting the stapled src, running tests, and installing it.

set -e

GOPATH=$HOME/workspace
PROJECT_ROOT=$GOPATH/src/github.com/rolandshoemaker
PROJECT=$PROJECT_ROOT/stapled

echo "Creating GOPATH in $GOPATH"
mkdir -p "$GOPATH"

echo "Setting GOPATH"
export GOPATH
echo 'export GOPATH=$HOME/workspace' >> ~/.bashrc

echo "Adding GOPATH bin/ to PATH"
export PATH=$PATH:$GOPATH/bin
echo 'export PATH=$PATH:$HOME/workspace/bin' >> ~/.bashrc

echo "Creating project structure in GOPATH"
mkdir -p "$PROJECT_ROOT"

echo "Linking project src to GOPATH"
ln -s /vagrant/ "$PROJECT"

echo "Installing godep"
go get github.com/tools/godep

pushd "$PROJECT"
  echo "Installing project"

  # Uncomment when vetting passes.
  #godep go vet ./...

  go test -v ./...
  go install ./...
popd

echo "Finished bootstrap-dev.sh"
