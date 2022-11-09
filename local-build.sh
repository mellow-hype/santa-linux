#/usr/bin/env bash
BREXT="$PWD/ext-tree"
BRBASE="$PWD/buildroot-2022.08"
BROUT="$PWD/br-output"

if [ ! -d "$BROUT" ]; then
    mkdir $BROUT
fi

cd $BRBASE
make O="$BROUT" BR2_EXTERNAL="$BREXT" rust-santa-clone-qemu_x86_64_defconfig
cd $BROUT
make -j12 santa_kmod-rebuild
make -j12 all

echo -E "\n\nDone -- images are under 'br-output/images/'"
