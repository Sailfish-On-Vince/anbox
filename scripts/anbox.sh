#!/bin/sh
export ANBOX_PLATFORM=sailfish
exec /usr/bin/anbox launch --package=org.anbox.appmgr --component=org.anbox.appmgr.AppViewActivity
