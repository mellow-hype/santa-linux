#/usr/bin/env bash

# drop into a shell in the container
sudo docker run \
    --cpus=12 \
    --rm \
    -it \
    -v "$PWD:/home/builder/santa" \
    santa-clone-builder $1
