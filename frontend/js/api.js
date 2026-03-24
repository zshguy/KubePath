/**
 * KubePath API Client
 * Handles all communication with the FastAPI backend.
 */

const API_BASE = '/api/v1';

const KubePathAPI = {
    /**
     * Make an API request.
     */
    async request(method, path, body = null) {
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json' },
        };
        if (body) opts.body = JSON.stringify(body);

        try {
            const res = await fetch(`${API_BASE}${path}`, opts);
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || `HTTP ${res.status}`);
            }
            return await res.json();
        } catch (err) {
            console.error(`API Error [${method} ${path}]:`, err);
            throw err;
        }
    },

    // ── Health ──
    health() { return this.request('GET', '/health'); },

    // ── Ingestion ──
    ingestKubernetes(kubeconfig = null) {
        return this.request('POST', '/ingest/kubernetes', kubeconfig ? { kubeconfig } : {});
    },

    ingestAWS(profile = null, region = 'us-east-1') {
        return this.request('POST', '/ingest/aws', { profile, region });
    },

    uploadConfig(sourceType, data) {
        return this.request('POST', '/ingest/upload', { source_type: sourceType, data });
    },

    async uploadFile(sourceType, file) {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch(`${API_BASE}/ingest/file?source_type=${sourceType}`, {
            method: 'POST',
            body: formData,
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || `HTTP ${res.status}`);
        }
        return res.json();
    },

    // ── Graph ──
    getGraph() { return this.request('GET', '/graph'); },
    getNodeDetail(uid) { return this.request('GET', `/graph/node/${encodeURIComponent(uid)}`); },

    // ── Analysis ──
    getAttackPaths(maxHops = 8) {
        return this.request('GET', `/analysis/paths?max_hops=${maxHops}`);
    },

    findPath(sourceUid, targetUid, maxHops = 10) {
        return this.request('POST', '/analysis/path', {
            source_uid: sourceUid,
            target_uid: targetUid,
            max_hops: maxHops,
        });
    },

    getCriticalNodes() { return this.request('GET', '/analysis/critical'); },
    getEntryPoints() { return this.request('GET', '/analysis/entry-points'); },
    getRiskScore() { return this.request('GET', '/analysis/score'); },
    getFindings() { return this.request('GET', '/analysis/findings'); },
    getRules() { return this.request('GET', '/analysis/rules'); },

    // ── Stats & Management ──
    getStats() { return this.request('GET', '/stats'); },
    clearGraph() { return this.request('DELETE', '/graph'); },
};
