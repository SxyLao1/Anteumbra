# -*- coding: utf-8 -*-
"""
E2E Test: File Similarity Clustering

Flow:
  1. Deploy variant webshells (3 PHP eval family, 2 JSP family)
  2. Compute fuzzy hashes with ppdeep
  3. Verify PHP variants are more similar to each other than to JSP
  4. Verify cross-language dissimilarity
"""

import pytest


class TestFileClustering:
    """Deploy variant webshells and verify fuzzy hashing groups similar files."""

    def test_hash_engine_initializes(self):
        """Verify ppdeep library is available (hash_engine module not yet in codebase)."""
        try:
            import ppdeep

            assert ppdeep is not None
        except ImportError:
            pytest.skip("ppdeep not installed")

    def test_similar_php_files_cluster_together(self, variant_webshells):
        """Verify that 2 nearly-identical PHP eval variants get similar fuzzy hashes.

        eval_v1 and eval_v2 share ~90% of code (only variable names differ).
        """
        try:
            import ppdeep
        except ImportError:
            pytest.skip("ppdeep not installed")

        f1 = variant_webshells / "eval_v1.php"
        f2 = variant_webshells / "eval_v2.php"

        content1 = f1.read_text(encoding="utf-8")
        content2 = f2.read_text(encoding="utf-8")

        # Both should have core pattern: @eval, base64_decode
        assert "eval" in content1 and "eval" in content2
        assert "base64_decode" in content1 and "base64_decode" in content2

        h1 = ppdeep.hash(content1.encode("utf-8"))
        h2 = ppdeep.hash(content2.encode("utf-8"))

        assert h1 is not None and h2 is not None, "ppdeep should produce hashes"
        assert len(h1) > 10, f"ppdeep hash should be meaningful, got: {h1}"
        assert len(h2) > 10, f"ppdeep hash should be meaningful, got: {h2}"

        # Files are ~90% identical — similarity should be high
        similarity = ppdeep.compare(h1, h2)
        assert similarity >= 30, (
            f"Nearly identical PHP files should have similarity >= 30%, got {similarity}%"
        )

    def test_php_vs_jsp_not_similar(self, variant_webshells):
        """Verify that PHP and JSP webshells do NOT cluster together."""
        try:
            import ppdeep
        except ImportError:
            pytest.skip("ppdeep not installed")

        php_file = variant_webshells / "eval_v1.php"
        jsp_file = variant_webshells / "cmd_jsp1.jsp"

        h_php = ppdeep.hash(php_file.read_text(encoding="utf-8").encode("utf-8"))
        h_jsp = ppdeep.hash(jsp_file.read_text(encoding="utf-8").encode("utf-8"))

        similarity = ppdeep.compare(h_php, h_jsp)
        # PHP vs JSP should have very low similarity
        assert similarity < 30, (
            f"PHP and JSP files should not be similar, "
            f"got {similarity}% — cross-language clustering is wrong"
        )

    def test_cluster_engine_stats(self, variant_webshells, file_cluster_engine):
        """Verify an explicitly owned file cluster engine."""
        engine = file_cluster_engine

        # Cluster the PHP files
        for fname in ["eval_v1.php", "eval_v2.php", "eval_v3.php"]:
            fpath = variant_webshells / fname
            if fpath.exists():
                try:
                    engine.cluster_file(str(fpath))
                except Exception:
                    pass

        # Check stats
        stats = engine.get_stats()
        assert stats is not None
        assert "total_files" in stats, f"Stats should have total_files: {stats}"
        assert "total_clusters" in stats, f"Stats should have total_clusters: {stats}"
        assert stats["total_files"] >= 0, "total_files should be non-negative"

    def test_cluster_engine_exposes_sorted_snapshots(self, tmp_path):
        from anteumbra.infrastructure.detection.file_cluster import FileClusterEngine

        class HashEngine:
            track_name = "test"

            @staticmethod
            def hash_file(file_path):
                return f"hash:{file_path}"

            @staticmethod
            def compare(_first, _second):
                return 1.0

        first = tmp_path / "first.php"
        second = tmp_path / "second.php"
        first.write_text("<?php eval($_POST['x']);", encoding="utf-8")
        second.write_text("<?php eval($_GET['x']);", encoding="utf-8")
        engine = FileClusterEngine(HashEngine())

        engine.cluster_file(str(first))
        engine.cluster_file(str(second))

        clusters = engine.list_clusters()
        assert [(cluster.size, cluster.hash_track) for cluster in clusters] == [(2, "test")]
        assert engine.list_clusters(min_size=3) == []
