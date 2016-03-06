#!/bin/bash

# boostrap-dev-admin.sh is run as root by Vagrant (see Vagrantfile) during
# provisioning. It should only do things that require root access. For non-root
# tasks use bootstrap-dev.sh
#
# Responsibilities:
#   - Downloading a fixed Go release for the dev env
#   - Installing Go system-wide
#   - Adding the Go installation to the system PATH

set -e

ARCH=amd64
OS=linux
VERSION=1.5.3

# This should be changed when $ARCH, $OS, $VERSION are updated. If there is 
# a SHA1 mismatch within a semantic version increase it merits investigation
# before changing the EXPECTED_SHA1
EXPECTED_SHA1=c5377eca4837968d043b681f00a852a262f0f5f6

# These should remain fixed unless Go hosting changes significantly
GODIST=https://storage.googleapis.com/golang/
GOTAR=go$VERSION.$OS-$ARCH.tar.gz

echo "Installing Git"
apt-get install git -y

pushd /tmp
  echo "Downloading Go $VERSION - this may take a while!!"
  wget $GODIST$GOTAR 2> /dev/null

  echo "$EXPECTED_SHA1 $GOTAR" | sha1sum -c -

  if [ $? -ne 0 ]; then
    echo "Terminated due to sha1 mismatch. Expected: $EXPECTED_SHA1"
    exit 1
  fi

  echo "Unpacking Go $VERSION to system"
  tar -C /usr/local -xzf $GOTAR

  echo "Adding Go to system default \$PATH"
  echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
  export PATH=$PATH:/usr/local/go/bin

popd
echo "Finished bootstrap-dev-admin.sh"
