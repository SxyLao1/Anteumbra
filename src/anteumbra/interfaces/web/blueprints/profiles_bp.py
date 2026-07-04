# -*- coding: utf-8 -*-
"""
v1.9.0: Profiles Blueprint — 威胁画像 + 文件聚类

从 admin_bp.py 拆分。
路由前缀: /admin/profiles/*, /admin/file-clusters, /admin/clusters/*
"""
from datetime import datetime
import logging
from pathlib import Path

from flask import (
    Blueprint, render_template, request, jsonify,
    current_app
)

from anteumbra.interfaces.web.auth import require_auth

logger = logging.getLogger(__name__)

# ── Blueprint ──────────────────────────────────────────────

profiles_bp = Blueprint('profiles', __name__, url_prefix='/admin')


# ── Profile List ───────────────────────────────────────────

@profiles_bp.route('/profiles')
@require_auth
def profiles_list():
    """画像列表页 — 服务端渲染 + 分页 + 搜索"""
    try:
        from anteumbra.application.threat_graph_service import get_threat_graph
        graph = get_threat_graph()
        all_profiles = graph.get_active_profiles(min_score=0.1)

        q = request.args.get('q', '').lower()
        if q:
            all_profiles = [p for p in all_profiles if
                q in p.profile_id.lower() or
                q in p.ua_fingerprint.lower() or
                q in p.tool_signature.lower() or
                any(q in ip for ip in p.ip_pool)]

        sort = request.args.get('sort', 'risk')
        if sort == 'time':
            all_profiles.sort(key=lambda p: p.last_seen or datetime.min, reverse=True)
        elif sort == 'traffic':
            all_profiles.sort(key=lambda p: len(p.ip_pool) + len(p.target_urls), reverse=True)

        per_page = 20
        page = max(1, request.args.get('page', 1, type=int))
        total = len(all_profiles)
        total_pages = max(1, (total + per_page - 1) // per_page)
        start = (page - 1) * per_page
        paginated = all_profiles[start:start + per_page]

        enriched = []
        now = datetime.now()
        for p in paginated:
            hours_ago = None
            if p.last_seen:
                hours_ago = round((now - p.last_seen).total_seconds() / 3600, 1)
            if p.status == "active":
                if hours_ago and hours_ago > 1:
                    p.status = "dormant"
                if hours_ago and hours_ago > 24:
                    p.status = "expired"

            enriched.append({
                "profile_id": p.profile_id,
                "ua_fingerprint": p.ua_fingerprint,
                "tool_signature": p.tool_signature,
                "risk_score": round(p.risk_score * 100, 1),
                "ip_count": len(p.ip_pool),
                "file_count": len(p.target_files),
                "url_count": len(p.target_urls),
                "status": p.status,
                "last_seen": p.last_seen.strftime("%Y-%m-%d %H:%M") if p.last_seen else "N/A",
                "hours_ago": hours_ago,
                "created_at": p.created_at.strftime("%Y-%m-%d %H:%M"),
                "sample_ips": list(p.ip_pool)[:5],
            })
        return render_template('admin/profiles.html', profiles=enriched,
            page=page, total_pages=total_pages, total=total, query=q)
    except Exception as e:
        current_app.logger.error(f"[PROFILES] list error: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@profiles_bp.route('/profiles/data')
@require_auth
def profiles_data():
    """画像数据 API"""
    try:
        from anteumbra.application.threat_graph_service import get_threat_graph
        graph = get_threat_graph()
        profiles = graph.get_active_profiles(min_score=0.1)
        result = []
        for p in profiles[:50]:
            result.append({
                "profile_id": p.profile_id,
                "ua_fingerprint": p.ua_fingerprint,
                "tool_signature": p.tool_signature,
                "risk_score": round(p.risk_score * 100, 1),
                "ip_count": len(p.ip_pool),
                "file_count": len(p.target_files),
                "url_count": len(p.target_urls),
                "status": p.status,
                "last_seen": p.last_seen.strftime("%Y-%m-%d %H:%M") if p.last_seen else "N/A",
                "created_at": p.created_at.strftime("%Y-%m-%d %H:%M"),
                "sample_ips": list(p.ip_pool)[:5],
                "sample_urls": list(p.target_urls)[:3],
            })
        return jsonify({"profiles": result, "total": len(profiles)})
    except Exception as e:
        current_app.logger.error(f"[PROFILES] data error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ── Profile Detail ─────────────────────────────────────────

@profiles_bp.route('/profiles/<profile_id>')
@require_auth
def profile_detail_page(profile_id):
    """画像详情（攻击链时间线 + 关联文件 + 关联记录）"""
    try:
        from anteumbra.application.threat_graph_service import get_threat_graph
        graph = get_threat_graph()
        profile = graph.query_profile(profile_id)
        if not profile:
            return render_template('admin/error.html', error="Profile not found"), 404

        # IP reputation (paginated)
        all_ips = sorted(profile.ip_pool)
        ip_total = len(all_ips)
        ip_per_page = 30
        ip_page = max(1, request.args.get('ip_page', 1, type=int))
        ip_total_pages = max(1, (ip_total + ip_per_page - 1) // ip_per_page)
        ip_start = (ip_page - 1) * ip_per_page
        ip_paginated = all_ips[ip_start:ip_start + ip_per_page]

        ip_details = []
        for ip in ip_paginated:
            rep = graph.query_ip(ip)
            if rep:
                ip_details.append({
                    "ip": ip, "event_count": rep.event_count,
                    "waf_score_avg": round(rep.waf_score_avg, 2),
                    "cluster_level": rep.cluster_level,
                    "first_seen": rep.first_seen, "last_seen": rep.last_seen,
                })
            else:
                ip_details.append({
                    "ip": ip, "event_count": 0, "waf_score_avg": 0,
                    "cluster_level": 0, "first_seen": profile.created_at,
                    "last_seen": profile.last_seen,
                })

        # File clusters
        file_clusters = []
        try:
            from anteumbra.application.file_cluster_service import get_file_cluster_engine
            from anteumbra.application.quarantine_service import get_quarantine_list
            ce = get_file_cluster_engine()
            quarantined_map = {}
            for q in get_quarantine_list(status="quarantined", limit=500):
                orig = q.get('original_path', '')
                if orig:
                    quarantined_map[orig] = q.get('quarantine_path', '')
            for fp in list(profile.target_files)[:30]:
                cluster = ce.get_cluster(fp)
                if cluster:
                    is_quarantined = fp in quarantined_map
                    q_path = quarantined_map.get(fp, '')
                    file_clusters.append({
                        "file": fp.rsplit(chr(92), 1)[-1].rsplit('/', 1)[-1],
                        "full_path": fp, "cluster_id": cluster.cluster_id,
                        "cluster_size": cluster.size, "samples": cluster.sample_files,
                        "quarantined": is_quarantined,
                        "quarantine_path": q_path.rsplit(chr(92), 1)[-1].rsplit('/', 1)[-1] if q_path else '',
                    })
            seen_cids = set()
            unique_clusters = []
            for fc in file_clusters:
                if fc["cluster_id"] not in seen_cids:
                    seen_cids.add(fc["cluster_id"])
                    unique_clusters.append(fc)
            file_clusters = unique_clusters
        except Exception:
            logger.debug("Failed to load file cluster data for profile detail", exc_info=True)

        # Linked records (bidirectional link)
        linked_records = []
        try:
            from anteumbra.application.registry_service import get_all as reg_get_all
            from anteumbra.application.quarantine_service import get_quarantine_list
            from anteumbra.infrastructure.utils.path_utils import path_to_key
            all_reg = reg_get_all(include_deleted=True)
            qmap = {}
            for q in get_quarantine_list(status="quarantined", limit=1000):
                orig = q.get("original_path", "")
                if orig:
                    qmap[orig] = q.get("quarantine_id", "")
            for fp in list(profile.target_files)[:50]:
                key = path_to_key(fp)
                for r in all_reg:
                    if r.get("file_path") == key:
                        linked_records.append({
                            "file_path": fp,
                            "display_name": Path(fp).name,
                            "detected_at": r.get("detected_at", "")[:16],
                            "quarantine_id": qmap.get(fp, ""),
                            "features": r.get("features", [])[:3],
                        })
                        break
        except Exception:
            logger.debug("Failed to load linked records for profile detail", exc_info=True)

        return render_template('admin/profile_detail.html',
            profile=profile, ip_details=ip_details,
            ip_page=ip_page, ip_total_pages=ip_total_pages, ip_total=ip_total,
            all_ips=list(all_ips),
            events=list(profile.attack_chain)[-50:],
            file_clusters=file_clusters,
            linked_records=linked_records)
    except Exception as e:
        current_app.logger.error(f"[PROFILES] detail error: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@profiles_bp.route('/profiles/<profile_id>/report')
@require_auth
def profile_report(profile_id):
    """攻击者画像报告（可打印 HTML）"""
    try:
        from anteumbra.application.threat_graph_service import get_threat_graph
        graph = get_threat_graph()
        profile = graph.query_profile(profile_id)
        if not profile:
            return render_template('admin/error.html', error="Profile not found"), 404

        return render_template('admin/profile_report.html',
            profile=profile,
            events=list(profile.attack_chain),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            mitre_tags=profile.mitre_tags if hasattr(profile, 'mitre_tags') else [],
        )
    except Exception as e:
        current_app.logger.error(f"[PROFILES] report error: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


# ── File Clusters ──────────────────────────────────────────

@profiles_bp.route('/file-clusters', methods=['GET'])
@require_auth
def file_clusters_page():
    """文件聚类列表页面"""
    try:
        from anteumbra.application.file_cluster_service import get_file_cluster_engine
        engine = get_file_cluster_engine()
        clusters = sorted(engine._clusters.values(), key=lambda c: c.size, reverse=True)
        enriched = []
        for c in clusters:
            # v2.0 fix: Include single-file clusters (was size < 2 filter)
            if c.size < 1:
                continue
            enriched.append({
                "cluster_id": c.cluster_id,
                "size": c.size,
                "samples": c.sample_files,
                "created": c.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "hash_track": c.hash_track if hasattr(c, 'hash_track') else 'unknown',
                "threshold": c.threshold if hasattr(c, 'threshold') else 0.80,
            })
        total_files = sum(c["size"] for c in enriched)
        multi_count = sum(1 for c in enriched if c["size"] > 2)
        avg_sim = round(1 - 1/(len(enriched) + 1), 2) if enriched else 0
        stats = {
            "total_clusters": len(enriched),
            "total_files": total_files,
            "multi_file_clusters": multi_count,
            "avg_similarity": avg_sim,
        }
        return render_template('admin/file_clusters.html', clusters=enriched, stats=stats, total=len(enriched))
    except Exception as e:
        current_app.logger.error(f"[PROFILES] clusters page error: {e}", exc_info=True)
        return render_template('admin/error.html', error=str(e)), 500


@profiles_bp.route('/clusters/stats')
@require_auth
def clusters_stats():
    """文件聚类统计 API"""
    try:
        from anteumbra.application.file_cluster_service import get_file_cluster_engine
        engine = get_file_cluster_engine()
        stats = engine.get_stats()
        top = sorted(engine._clusters.values(), key=lambda c: c.size, reverse=True)[:10]
        stats["top_clusters"] = [{
            "cluster_id": c.cluster_id,
            "size": c.size,
            "samples": c.sample_files,
            "created": c.created_at.strftime("%H:%M:%S"),
        } for c in top if c.size > 1]
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
