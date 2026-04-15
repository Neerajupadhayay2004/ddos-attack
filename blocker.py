"""
blocker.py  —  IP blocking / allowlisting system
Uses iptables on Linux (requires root) with in-memory fallback.
"""
import os
import time
import logging
import subprocess
from collections import defaultdict
from threading import Lock

logger = logging.getLogger(__name__)

USE_IPTABLES = os.geteuid() == 0 if hasattr(os, 'geteuid') else False


class IPBlocker:
    def __init__(self, auto_unblock_after=300):
        """
        auto_unblock_after: seconds before auto-unblocking (0 = permanent)
        """
        self._blocked    = {}          # ip -> {'reason', 'blocked_at', 'expires'}
        self._whitelist  = set()
        self._lock       = Lock()
        self.auto_unblock_after = auto_unblock_after
        self._hit_counts = defaultdict(int)

        # Whitelist localhost + common safe IPs
        self._whitelist.update(['127.0.0.1', '::1', '0.0.0.0'])

    # ── Core API ──────────────────────────────────────────────────────────────

    def block(self, ip: str, reason: str = 'DDoS Attack Detected') -> dict:
        if ip in self._whitelist:
            return {'success': False, 'msg': f'{ip} is whitelisted'}

        with self._lock:
            if ip in self._blocked:
                return {'success': False, 'msg': f'{ip} already blocked'}

            expires = (time.time() + self.auto_unblock_after
                       if self.auto_unblock_after > 0 else None)

            self._blocked[ip] = {
                'ip':         ip,
                'reason':     reason,
                'blocked_at': time.time(),
                'expires':    expires,
            }
            self._apply_iptables(ip, action='block')
            logger.info("BLOCKED: %s — %s", ip, reason)
            return {'success': True, 'msg': f'{ip} blocked', 'expires': expires}

    def unblock(self, ip: str) -> dict:
        with self._lock:
            if ip not in self._blocked:
                return {'success': False, 'msg': f'{ip} not in blocked list'}
            del self._blocked[ip]
            self._apply_iptables(ip, action='unblock')
            logger.info("UNBLOCKED: %s", ip)
            return {'success': True, 'msg': f'{ip} unblocked'}

    def is_blocked(self, ip: str) -> bool:
        self._expire_check()
        with self._lock:
            return ip in self._blocked

    def get_blocked_list(self) -> list:
        self._expire_check()
        with self._lock:
            now = time.time()
            result = []
            for ip, info in self._blocked.items():
                remaining = None
                if info['expires']:
                    remaining = max(0, int(info['expires'] - now))
                result.append({
                    **info,
                    'remaining_seconds': remaining,
                    'duration_blocked':  int(now - info['blocked_at']),
                })
            return result

    def record_hit(self, ip: str):
        """Track hit count per IP for rate-based auto-blocking"""
        self._hit_counts[ip] += 1
        return self._hit_counts[ip]

    def get_hit_count(self, ip: str) -> int:
        return self._hit_counts.get(ip, 0)

    def clear_hit_count(self, ip: str):
        self._hit_counts.pop(ip, None)

    def whitelist(self, ip: str):
        self._whitelist.add(ip)
        if ip in self._blocked:
            self.unblock(ip)

    def get_stats(self):
        self._expire_check()
        return {
            'total_blocked':    len(self._blocked),
            'whitelisted':      len(self._whitelist),
            'using_iptables':   USE_IPTABLES,
            'auto_unblock_sec': self.auto_unblock_after,
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _expire_check(self):
        """Remove expired blocks"""
        now = time.time()
        with self._lock:
            expired = [ip for ip, info in self._blocked.items()
                       if info['expires'] and now > info['expires']]
            for ip in expired:
                del self._blocked[ip]
                self._apply_iptables(ip, action='unblock')
                logger.info("AUTO-UNBLOCKED (expired): %s", ip)

    @staticmethod
    def _apply_iptables(ip: str, action: str):
        """Apply iptables rule — silently skip if not root or iptables unavailable"""
        if not USE_IPTABLES:
            return
        flag = '-I' if action == 'block' else '-D'
        cmd  = ['iptables', flag, 'INPUT', '-s', ip, '-j', 'DROP']
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
        except Exception as e:
            logger.debug("iptables skipped: %s", e)


# Singleton
_blocker = None

def get_blocker() -> IPBlocker:
    global _blocker
    if _blocker is None:
        _blocker = IPBlocker(auto_unblock_after=300)
    return _blocker