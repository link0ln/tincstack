#!/usr/bin/env bash
# probe-apps.sh <out-dir> -- two code-less, debuggable APKs for the split-routing
# proof (split-routing-on-emulator.sh): net.tincstack.probe.a and
# net.tincstack.probe.b, each with INTERNET.
#
# They exist only to own a UID. `adb shell run-as <pkg> ping ...` runs ping as
# that app's UID (debuggable is what run-as needs, INTERNET gives the inet
# group), and Android routes a UID into the VPN or not by the
# AllowApplication / DisallowApplication lists. So a ping from probe.a and one
# from probe.b are two different apps' traffic, per-UID routed like any app's.
#
# Built with aapt2 + apksigner from the SDK inside the android-build image
# (nothing on the host), signed with a throwaway key generated on the spot.
set -euo pipefail
OUT=$(mkdir -p "${1:?usage: probe-apps.sh <out-dir>}" && cd "$1" && pwd)
IMAGE=${BUILD_IMAGE:-tincstack/android-build}
BT=${BUILD_TOOLS:-34.0.0}
API=${API:-34}

docker run --rm -v "$OUT":/out -v /opt/android-sdk:/opt/android-sdk:ro -e BT="$BT" -e API="$API" \
    --entrypoint bash "$IMAGE" -euo pipefail -c '
cd /tmp
keytool -genkeypair -keystore probe.jks -storepass probepass -keypass probepass -alias probe \
    -keyalg RSA -keysize 2048 -validity 30 -dname CN=probe >/dev/null 2>&1
for n in a b; do
    mkdir -p $n
    cat > $n/AndroidManifest.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="net.tincstack.probe.$n" android:versionCode="1" android:versionName="1">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="$API" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="tincstack probe $n" android:hasCode="false" android:debuggable="true" />
</manifest>
EOF
    /opt/android-sdk/build-tools/$BT/aapt2 link --manifest $n/AndroidManifest.xml \
        -I /opt/android-sdk/platforms/android-$API/android.jar -o $n/unsigned.apk
    /opt/android-sdk/build-tools/$BT/zipalign -f 4 $n/unsigned.apk $n/aligned.apk
    /opt/android-sdk/build-tools/$BT/apksigner sign --ks probe.jks --ks-pass pass:probepass \
        --out /out/probe-$n.apk $n/aligned.apk
done
ls -l /out'
