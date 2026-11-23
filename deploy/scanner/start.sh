#!/bin/sh
# Starts the scanner as the nasscan user (uid 10001), able to read every file under /scan.
#
# The server stack starts this as root with only DAC_READ_SEARCH, SETUID, SETGID and SETPCAP.
# It switches to nasscan keeping DAC_READ_SEARCH alone (read any file and list any folder,
# whatever its permissions; never write), so folders like a chmod 700 home directory get
# scanned too. /scan is mounted read-only either way. With NASSCAN_SCANNER_READ_ALL=false it
# keeps nothing, and the scanner reads only what uid 10001 may read.
set -eu

if [ "$(id -u)" != 0 ]; then
    exec nasscan scanner
fi

case "${NASSCAN_SCANNER_READ_ALL:-true}" in
    false | 0 | no | off)
        exec setpriv --reuid=nasscan --regid=nasscan --clear-groups --inh-caps=-all \
            --bounding-set=-all nasscan scanner
        ;;
    *)
        exec setpriv --reuid=nasscan --regid=nasscan --clear-groups \
            --inh-caps=-all,+dac_read_search --ambient-caps=-all,+dac_read_search \
            --bounding-set=-all,+dac_read_search nasscan scanner
        ;;
esac
