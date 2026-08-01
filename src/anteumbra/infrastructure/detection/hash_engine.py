# -*- coding: utf-8 -*-
"""
v1.8.3: 文件相似度哈希引擎 — 三轨降级
Track 1: ssdeep (CTPH, best accuracy, needs libfuzzy C library)
Track 2: py-tlsh (Trend Micro TLSH, pure Python)
Track 3: Built-in SimHash (zero dependency, always available)

Design from PROJECT_MASTER Section 8.
"""

import logging

logger = logging.getLogger("monitor.hash_engine")


class SimHash:
    """内置 SimHash — 零依赖，永不失败"""

    @staticmethod
    def hash(data: bytes) -> str:
        """计算 64-bit SimHash fingerprint，返回 hex string"""
        if not data:
            return "0" * 16
        # Simple weighted SimHash
        v = [0] * 64
        # Use sliding window of 4 bytes
        for i in range(len(data) - 3):
            chunk = int.from_bytes(data[i : i + 4], "little")
            for bit in range(64):
                if chunk & (1 << (bit % 32)):
                    v[bit] += 1
                else:
                    v[bit] -= 1
        # Threshold to bits
        result = 0
        for bit in range(64):
            if v[bit] > 0:
                result |= 1 << bit
        return f"{result:016x}"

    @staticmethod
    def distance(h1: str, h2: str) -> int:
        """Hamming distance between two SimHash values"""
        if len(h1) != len(h2):
            return 64
        d = 0
        for i in range(0, len(h1), 16):
            a = int(h1[i : i + 16], 16)
            b = int(h2[i : i + 16], 16)
            d += bin(a ^ b).count("1")
        return d

    @staticmethod
    def similarity(h1: str, h2: str) -> float:
        """相似度 0.0-1.0（基于海明距离）"""
        dist = SimHash.distance(h1, h2)
        return max(0.0, 1.0 - dist / 64.0)


class HashEngine:
    """
    三轨哈希引擎：ssdeep → py-tlsh → SimHash
    安装时自动探测，运行时自动降级，永不失败
    """

    def __init__(self):
        self._ssdeep = None
        self._tlsh = None
        self._simhash = SimHash()
        self._active_track = "simhash"
        self._init()

    def _init(self):
        # Track 1: ssdeep (C library, best performance)
        try:
            import ssdeep

            self._ssdeep = ssdeep
            self._active_track = "ssdeep"
            logger.info("[HASH] ssdeep loaded (Track 1 — C)")
            return
        except ImportError:
            logger.info("[HASH] ssdeep C library not available, trying ppdeep")

        # Track 1.5: ppdeep (pure Python CTPH, same algorithm as ssdeep)
        try:
            import ppdeep

            self._ssdeep = ppdeep  # same API, same output format
            self._active_track = "ppdeep"
            logger.info("[HASH] ppdeep loaded (Track 1.5 — pure Python CTPH)")
            return
        except ImportError:
            logger.info("[HASH] ppdeep not available, trying py-tlsh")

        # Track 2: py-tlsh
        try:
            import tlsh

            self._tlsh = tlsh
            self._active_track = "tlsh"
            logger.info("[HASH] py-tlsh loaded (Track 2)")
            return
        except ImportError:
            logger.info("[HASH] py-tlsh not available, using built-in SimHash")

        # Track 3: always available
        logger.info("[HASH] SimHash active (Track 3 — zero dependency)")

    @property
    def track_name(self) -> str:
        return self._active_track

    def hash_file(self, file_path: str) -> str:
        """计算文件哈希，返回 track:hash 格式"""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            if len(data) > 5 * 1024 * 1024:  # Skip files > 5MB
                return "skip:too_large"

            if self._ssdeep:
                h = self._ssdeep.hash(data)
                return f"ssdeep:{h}"
            elif self._tlsh:
                h = self._tlsh.hash(data)
                return f"tlsh:{h}"
            else:
                h = self._simhash.hash(data)
                return f"simhash:{h}"
        except Exception as e:
            logger.debug(f"[HASH] Failed to hash {file_path}: {e}")
            return f"error:{e}"

    def compare(self, hash1: str, hash2: str) -> float:
        """比较两个哈希值的相似度 (0.0-1.0)"""
        try:
            t1, v1 = hash1.split(":", 1)
            t2, v2 = hash2.split(":", 1)
            if t1 != t2 or t1 in ("skip", "error"):
                return 0.0

            if t1 == "ssdeep":
                return self._ssdeep.compare(v1, v2) / 100.0
            elif t1 == "tlsh":
                dist = self._tlsh.diff(v1, v2)
                return max(0.0, 1.0 - dist / 300.0)
            else:  # simhash
                return self._simhash.similarity(v1, v2)
        except Exception:
            return 0.0
