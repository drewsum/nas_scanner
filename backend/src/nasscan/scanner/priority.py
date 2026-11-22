"""Lowering the scanner's own CPU and IO priority. Both only ever lower it, which needs no
capabilities, so it works in the stack's cap_drop ALL containers. Failures are logged, never
fatal: the read throttle is the main control anyway (ZFS largely schedules its own IO)."""

import ctypes
import logging
import os
import platform

from nasscan.config import Settings

log = logging.getLogger(__name__)

# ioprio_set(2): no glibc wrapper, so by syscall number.
IOPRIO_SYSCALL = {"x86_64": 251, "aarch64": 30}
IOPRIO_WHO_PROCESS = 1
IOPRIO_CLASS_IDLE = 3
IOPRIO_CLASS_SHIFT = 13


def lower_priority(settings: Settings) -> None:
    if settings.scanner_nice and hasattr(os, "nice"):
        try:
            current = os.nice(0)
            if current < settings.scanner_nice:
                os.nice(settings.scanner_nice - current)
            log.info("CPU priority: nice %d", os.nice(0))
        except OSError as exc:
            log.warning("couldn't lower CPU priority: %s", exc)
    if settings.scanner_ionice_idle:
        number = IOPRIO_SYSCALL.get(platform.machine())
        if platform.system() != "Linux" or number is None:
            return
        libc = ctypes.CDLL(None, use_errno=True)
        value = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT
        # who=0: the calling thread; worker threads created afterwards inherit it.
        if libc.syscall(number, IOPRIO_WHO_PROCESS, 0, value) != 0:
            log.warning("couldn't set idle IO priority: %s", os.strerror(ctypes.get_errno()))
        else:
            log.info("IO priority: idle class")
