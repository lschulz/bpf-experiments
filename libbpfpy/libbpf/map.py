"""Helpers for working with BPF maps from Python.
"""

from ctypes import *

from .bpf import *


class Map:
    """Pinned BPF map. Can be used as context manager in a `with` statement."""

    def __init__(self, pin_path: bytes, map_type: int):
        """Open a BPF map pinned at `pin_path`.
        :param map_type: Expected map type. One of bpf.BPF_MAP_TYPE_*
        """
        self.fd = bpf_obj_get(pin_path)
        try:
            info = get_map_info_by_fd(self.fd)
            if info.type != map_type:
                raise BpfError("Map type mismatch")
            self.map_type = map_type
            self.key_size = info.key_size
            self.value_size = info.value_size
        except:
            close(self.fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self.fd > 0:
            close(self.fd)
            self.fd = -1

    def lookup(self, key, value) -> bool:
        """Retrieve a value from the map. `key` and `value` must be appropriate ctypes types.
        :return: True if the element was found, otherwise false.
        """
        if not self._verify_arg_size(sizeof(key), sizeof(value)):
            raise BpfError("Invalid key/value size")
        return map_lookup_elem(self.fd, key, value)

    def _verify_arg_size(self, key_size: int, value_size: int):
        if self.map_type == BPF_MAP_TYPE_PERCPU_HASH or self.map_type == BPF_MAP_TYPE_ARRAY:
            return key_size >= self.key_size and value_size >= (self.value_size * os.cpu_count())
        else:
            return key_size >= self.key_size and value_size >= self.value_size
