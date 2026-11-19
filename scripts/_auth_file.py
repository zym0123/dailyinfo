"""Request-time cache for an atomically replaced local authentication file."""

from pathlib import Path
from threading import Lock


class ReloadingKeyFile:
    def __init__(self, path: Path, read_keys):
        self.path = Path(path)
        self._read_keys = read_keys
        self._lock = Lock()
        self._stamp = None
        self._keys = None

    def _signature(self):
        status = self.path.stat()
        return (status.st_dev, status.st_ino, status.st_mtime_ns, status.st_ctime_ns, status.st_size)

    def read(self):
        with self._lock:
            for _ in range(3):
                before = self._signature()
                if self._stamp == before:
                    return self._keys
                self._stamp = None
                self._keys = None
                keys = self._read_keys(self.path)
                if not keys:
                    raise RuntimeError("authentication_file_empty")
                if self._signature() == before:
                    self._stamp, self._keys = before, keys
                    return keys
            raise RuntimeError("authentication_file_changed_during_read")
