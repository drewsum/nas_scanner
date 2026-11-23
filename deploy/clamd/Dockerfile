# The official ClamAV image plus fangfrisch, which adds unofficial signature sets (Sanesecurity,
# URLhaus, ...) to freshclam's official ones. CI publishes it as
# ghcr.io/drewsum/nas_scanner:clamd-<tag>. The scanner streams files to it over TCP 3310.
FROM clamav/clamav:1.4

# clamd.conf, through the image's CLAMD_CONF_* mechanism (applied at every start):
# - the scanner streams files of up to NASSCAN_CLAMD_STREAM_MAX_MB (400 MB), so allow 512 MB;
# - scan inside archives that big;
# - reload signatures in place instead of loading a second copy alongside (halves the RAM
#   peak during reloads; scans wait a few seconds instead).
ENV CLAMD_CONF_StreamMaxLength=512M \
    CLAMD_CONF_MaxFileSize=512M \
    CLAMD_CONF_MaxScanSize=1024M \
    CLAMD_CONF_ConcurrentDatabaseReload=no \
    FANGFRISCH_SANESECURITY=yes \
    FANGFRISCH_URLHAUS=no \
    FANGFRISCH_INTERVAL_MINUTES=60

# URLhaus stopped publishing ClamAV signatures (410 Gone, late 2026); FANGFRISCH_URLHAUS=yes
# turns it back on should that change.
RUN apk add --no-cache python3 \
 && python3 -m venv /opt/fangfrisch \
 && /opt/fangfrisch/bin/pip install --no-cache-dir fangfrisch==1.9.2 \
 && ln -s /opt/fangfrisch/bin/fangfrisch /usr/local/bin/fangfrisch

COPY --chmod=755 nasscan-clamd-init.sh /nasscan-clamd-init
ENTRYPOINT ["/nasscan-clamd-init"]
