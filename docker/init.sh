#!/bin/bash
CONTAINER="santa-clone-builder"

sudo docker build -t $CONTAINER .
echo "Container name is: $CONTAINER"

