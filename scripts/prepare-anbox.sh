#!/bin/sh

ANBOX_DATA=/var/lib/anbox

OVERLAY_DIR=$ANBOX_DATA/overlay
ROOTFS=$ANBOX_DATA/rootfs
ROOTFS_FILE=$ANBOX_DATA/android.img
WORKDIR=$ANBOX_DATA/work

EXTRA_BIND_MOUNTS=/var/lib/anbox/containers/default/extra_bind_mounts

LIBS="/vendor/lib/egl/libEGL_adreno.so /vendor/lib/egl/libGLESv1_CM_adreno.so /vendor/lib/egl/libGLESv2_adreno.so "

if [ -f "/system/lib/hw/gralloc.$(getprop ro.product.device).so" ];
then
  LIBS+="/system/lib/hw/gralloc.$(getprop ro.product.device).so"
else
  LIBS+="/system/lib/hw/gralloc.$(getprop ro.board.platform).so"
fi

# we have no ldd for android libs
find_deps() {
    if [ "$2" != "" ]; then
        eval "PREV_DEPS=\$$1"
        if [[ "$PREV_DEPS" != *"$2"* ]]; then
            eval "$1+='$2 '"
            A=$(find -L /vendor/ /system/ | grep $2)
            if [ "$A" != "" ]; then
                D=$(strings $A | grep "\.so$" | grep -v $2)
                for f in $D; do
                    find_deps $1 $f
                done
            fi
        fi
    fi
}

echo "Finding dependancies of $LIBS"
DEPS=
for f in $LIBS; do
    find_deps DEPS $f
done

echo "Found dependancies"
echo $DEPS

echo "Ignoring files which are already in rootfs"
mkdir -p $ROOTFS
mount $ROOTFS_FILE $ROOTFS

mkdir -p $WORKDIR

NEW_DEPS=
for f in $DEPS; do
    if [ "$(find $ROOTFS/system/ | grep $f)" == "" ]; then
        NEW_DEPS+="$f "
    else
        echo $f" already in rootfs"
    fi
done

umount $ROOTFS

DEPS=$NEW_DEPS

echo "Copying everything to overlay (32-bit)"
for f in $DEPS; do
    # Ignore 64-bit libs
    if [[ "$f" = *"/lib64/"* ]]; then
        continue
    fi
    # don't put find /vendor/ /system/. because we need to prefer the /vendor location
    FULL_NAME=$(find /odm/lib/ | grep $(basename $f))
    if [ "$FULL_NAME" == "" ]; then
        FULL_NAME=$(find /vendor/lib/ | grep $(basename $f))
    fi
    if [ "$FULL_NAME" == "" ]; then
        FULL_NAME=$(find /system/lib/ | grep $(basename $f))
    fi
    if [ "$FULL_NAME" != "" ]; then
        echo $f" -> "$FULL_NAME
        mkdir -p $(dirname $OVERLAY_DIR/$FULL_NAME)
        cp $FULL_NAME $OVERLAY_DIR/$FULL_NAME
    else
        echo "ignoring possibly optional dependancy: $f"
    fi
done

echo "Copying everything to overlay (64-bit)"
for f in $DEPS; do
    # Ignore 32-bit libs
    if [[ "$f" = *"/lib/"* ]]; then
        continue
    fi
    # don't put find /vendor/ /system/. because we need to prefer the /vendor location
    FULL_NAME=$(find /odm/lib64/ | grep $(basename $f))
    if [ "$FULL_NAME" == "" ]; then
        FULL_NAME=$(find /vendor/lib64/ | grep $(basename $f))
    fi
    if [ "$FULL_NAME" == "" ]; then
        FULL_NAME=$(find /system/lib64/ | grep $(basename $f))
    fi
    if [ "$FULL_NAME" != "" ]; then
        echo $f" -> "$FULL_NAME
        mkdir -p $(dirname $OVERLAY_DIR/$FULL_NAME)
        cp $FULL_NAME $OVERLAY_DIR/$FULL_NAME
    else
        echo "ignoring possibly optional dependancy: $f"
    fi
done

mkdir -p $OVERLAY_DIR/vendor/lib/egl
mkdir -p $OVERLAY_DIR/system/lib/egl
mkdir -p $OVERLAY_DIR/system/lib/hw
cp /system/lib/egl/egl.cfg $OVERLAY_DIR/system/lib/egl/egl.cfg
cp /system/lib64/egl/egl.cfg $OVERLAY_DIR/system/lib64/egl/egl.cfg
if [ -f "/system/lib/hw/gralloc.$(getprop ro.product.device).so" ];
then
  cp /system/lib/hw/gralloc.$(getprop ro.product.device).so $OVERLAY_DIR/system/lib/hw/gralloc.default.so
  cp /system/lib/hw/gralloc.$(getprop ro.product.device).so $OVERLAY_DIR/system/lib/hw/gralloc.goldfish.so
else
  cp /system/lib/hw/gralloc.$(getprop ro.board.platform).so $OVERLAY_DIR/system/lib/hw/gralloc.default.so
  cp /system/lib/hw/gralloc.$(getprop ro.board.platform).so $OVERLAY_DIR/system/lib/hw/gralloc.goldfish.so
fi

cd $OVERLAY_DIR
if [ -d "odm/lib/" ]; then
ln -s /odm/lib/* vendor/lib/
ln -s /odm/lib/egl/* vendor/lib/egl/
fi
ln -s /vendor/lib/egl/libGLESv2_adreno.so system/lib/egl/libGLESv2_emulation.so
ln -s /vendor/lib/egl/libGLESv1_CM_adreno.so system/lib/egl/libGLESv1_CM_emulation.so
# softlink do not work, why?
#ln -s /vendor/lib/egl/libEGL_adreno.so system/lib/egl/libEGL_emulation.so
cp /vendor/lib/egl/libEGL_adreno.so system/lib/egl/libEGL_emulation.so
cp /vendor/lib/egl/libEGL_adreno.so system/lib/egl/libGLES_emulation.so

echo "Setting up extra bind mounts"
mkdir -p /var/lib/anbox/containers/default/
echo "/dev/ion"
echo "/dev/ion dev/ion" > $EXTRA_BIND_MOUNTS

for f in /dev/kgsl*; do
    echo $f
    echo "/dev/$(basename $f) dev/$(basename $f)" >> $EXTRA_BIND_MOUNTS
done

echo "Setting up wayland socket"

mkdir -p $OVERLAY_DIR/run/display

echo "/run/display"
echo "/run/display run/display" >> $EXTRA_BIND_MOUNTS

echo "/dev/fb0"
echo "/dev/fb0 dev/fb0" >> $EXTRA_BIND_MOUNTS

echo "/dev/uinput"
echo "/dev/uinput dev/uinput" >> $EXTRA_BIND_MOUNTS
