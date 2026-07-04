# -*- coding: utf-8 -*-
"""
v1.8.3: 文件相似度聚类引擎

基于 ssdeep/py-tlsh/SimHash 哈希，将相似文件归入同一簇。
阈值 > 0.80 归为同一文件簇（代表同一工具生成的变种）。
"""
import hashlib
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from anteumbra.infrastructure.detection.hash_engine import HashEngine, get_hash_engine

logger = logging.getLogger("monitor.file_cluster")


class FileCluster:
    """文件簇——一组相似度高的文件"""

    def __init__(self, cluster_id: str):
        self.cluster_id = cluster_id
        self.files: Dict[str, str] = {}  # {file_path: hash_value}
        self.representative_hash: str = ""  # 簇的代表哈希（第一个文件）
        self.created_at = datetime.now()
        self.updated_at = datetime.now()

    def add_file(self, file_path: str, hash_value: str) -> bool:
        """添加文件到簇。ppdeep 对小文件效果差，增加内容兜底。"""
        if not self.representative_hash:
            self.representative_hash = hash_value
            self.files[file_path] = hash_value
            return True

        engine = get_hash_engine()
        sim = engine.compare(self.representative_hash, hash_value)

        # v2.0: 小文件兜底 — CTPH 对小文件( < 4KB )基本无效
        if sim < 0.80:
            try:
                import os as _os
                def _safe_stat(p):
                    try: return _os.path.getsize(p)
                    except Exception: return 0
                sz_new = _safe_stat(file_path)
                first_file = next(iter(self.files.keys()))
                sz_old = _safe_stat(first_file)
                if sz_new > 0 and sz_old > 0 and sz_new < 4096 and sz_old < 4096:
                    if abs(sz_new - sz_old) / max(sz_new, 1) < 0.15:
                        ext_new = _os.path.splitext(file_path)[1].lower()
                        ext_old = _os.path.splitext(first_file)[1].lower()
                        if ext_new == ext_old:
                            sim = 0.85
                            logger.info(f"[CLUSTER] Small file fallback: {_os.path.basename(file_path)} ~ {_os.path.basename(first_file)}")
            except Exception:
                logger.debug("Small file size fallback check failed in cluster add_file", exc_info=True)

        if sim >= 0.80:
            self.files[file_path] = hash_value
            self.updated_at = datetime.now()
            return True
        return False

    @property
    def size(self) -> int:
        return len(self.files)

    @property
    def sample_files(self) -> List[str]:
        """返回簇中文件名示例"""
        return [Path(p).name for p in list(self.files.keys())[:5]]


class FileClusterEngine:
    """文件聚类引擎"""

    def __init__(self, engine: Optional[HashEngine] = None):
        self.hash_engine = engine or get_hash_engine()
        self._clusters: Dict[str, FileCluster] = {}  # cluster_id -> FileCluster
        self._file_index: Dict[str, str] = {}  # file_path -> cluster_id

    def cluster_file(self, file_path: str) -> Tuple[Optional[str], str]:
        """
        对文件计算哈希并尝试归入现有簇。
        返回 (cluster_id_or_None, hash_value)
        """
        hash_value = self.hash_engine.hash_file(file_path)
        if hash_value.startswith("skip:") or hash_value.startswith("error:"):
            return None, hash_value

        # Try to add to existing cluster
        for cid, cluster in self._clusters.items():
            if cluster.add_file(file_path, hash_value):
                self._file_index[file_path] = cid
                logger.debug(f"[CLUSTER] {Path(file_path).name} -> existing cluster {cid[:8]} ({cluster.size} files)")
                return cid, hash_value

        # Create new cluster
        cid = hashlib.sha256(hash_value.encode()).hexdigest()[:12]
        cluster = FileCluster(cid)
        cluster.add_file(file_path, hash_value)
        self._clusters[cid] = cluster
        self._file_index[file_path] = cid
        logger.info(f"[CLUSTER] New cluster {cid[:8]}: {Path(file_path).name}")
        return cid, hash_value

    def get_cluster(self, file_path: str) -> Optional[FileCluster]:
        """获取文件所属的簇"""
        cid = self._file_index.get(file_path)
        if cid:
            return self._clusters.get(cid)
        return None

    def get_cluster_by_id(self, cluster_id: str) -> Optional[FileCluster]:
        return self._clusters.get(cluster_id)

    def get_cluster_for_files(self, file_paths: List[str]) -> Dict[str, Optional[FileCluster]]:
        """批量查询文件所属簇"""
        return {fp: self.get_cluster(fp) for fp in file_paths}

    def get_stats(self) -> Dict:
        """返回聚类统计"""
        total_files = sum(c.size for c in self._clusters.values())
        multi_file_clusters = sum(1 for c in self._clusters.values() if c.size > 1)
        return {
            "total_clusters": len(self._clusters),
            "total_files": total_files,
            "multi_file_clusters": multi_file_clusters,
            "largest_cluster_size": max((c.size for c in self._clusters.values()), default=0),
            "avg_files_per_cluster": round(total_files / max(len(self._clusters), 1), 1),
            "active_track": self.hash_engine.track_name,
        }


# Singleton
_cluster_engine: Optional[FileClusterEngine] = None


def get_file_cluster_engine() -> FileClusterEngine:
    global _cluster_engine
    if _cluster_engine is None:
        _cluster_engine = FileClusterEngine()
        logger.info(f"[CLUSTER] Engine initialized: track={_cluster_engine.hash_engine.track_name}")
    return _cluster_engine
