#!/bin/sh
# Starts a fangfrisch refresh loop next to the image's usual freshclam + clamd (/init).
set -eu

CONF=/etc/fangfrisch.conf
yes_no() { case "$(echo "${1:-}" | tr 'A-Z' 'a-z')" in yes|true|1|on) echo yes ;; *) echo no ;; esac; }

{
  echo "[DEFAULT]"
  echo "db_url = sqlite:////var/lib/clamav/fangfrisch/db.sqlite"
  echo "local_directory = /var/lib/clamav"
  echo "log_level = INFO"
  # Tell clamd to load what changed.
  echo "on_update_exec = sh -c 'printf \"zRELOAD\\0\" | nc 127.0.0.1 3310'"
  echo "on_update_timeout = 60"
  echo
  echo "[sanesecurity]"
  echo "enabled = $(yes_no "$FANGFRISCH_SANESECURITY")"
  echo
  echo "[urlhaus]"
  echo "enabled = $(yes_no "$FANGFRISCH_URLHAUS")"
  if [ -n "${FANGFRISCH_MALWAREPATROL_RECEIPT:-}" ]; then
    echo
    echo "[malwarepatrol]"
    echo "enabled = yes"
    echo "receipt = $FANGFRISCH_MALWAREPATROL_RECEIPT"
  fi
  if [ -n "${FANGFRISCH_SECURITEINFO_CUSTOMER_ID:-}" ]; then
    echo
    echo "[securiteinfo]"
    echo "enabled = yes"
    echo "customer_id = $FANGFRISCH_SECURITEINFO_CUSTOMER_ID"
  fi
} > "$CONF"
chmod 644 "$CONF"

# As clamav, who owns the database folder: with every capability but CHOWN, SETUID and SETGID
# dropped, root can't write into it.
su -s /bin/sh clamav -c "mkdir -p /var/lib/clamav/fangfrisch"

(
  # Let freshclam's first download and clamd's start go first.
  sleep "${FANGFRISCH_START_DELAY:-60}"
  while true; do
    su -s /bin/sh clamav -c "fangfrisch --conf $CONF initdb >/dev/null 2>&1; fangfrisch --conf $CONF refresh" \
      || echo "fangfrisch: refresh failed; trying again later"
    sleep "$(( ${FANGFRISCH_INTERVAL_MINUTES:-60} * 60 ))"
  done
) &

exec /init "$@"
