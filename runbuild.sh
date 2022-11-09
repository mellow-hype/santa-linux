#/usr/bin/env bash

if [ "$#" != 2 ]; then
    echo "usage: $0 </path/to/build/output> <build-target>"
    exit 1
fi

BUILDLOC="$1"
TARGET="$2"
CORES=$(( $(nproc)-1 ))

if [ $CORES -gt 12 ]; then
    THREADS=$(( $CORES-4 ))
elif [ $CORES -gt 8 && $CORES -lt 12 ]; then
    THREADS=$(( $CORES-2 ))
elif [ $CORES -lt 8 ]; then
    THREADS=$(( $CORES-1 ))
fi

cd $BUILDLOC
make -j${THREADS} ${TARGET}
make -j${THREADS} all

../qemu-run.sh images
