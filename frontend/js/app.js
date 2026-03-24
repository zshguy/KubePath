/**
 * KubePath Application Controller
 * Main app logic, state management, and initialization.
 */

const KubePathApp = {
    state: {
        graphLoaded: false,
        selectedNode: null,
    },

    /**
     * Initialize the application.
     */
    async init() {
        console.log('%c ⬡ KubePath v1.0.0 ', 'background: linear-gradient(135deg, #00f5d4, #7b61ff); color: #000; font-size: 14px; font-weight: bold; padding: 4px 8px; border-radius: 4px;');

        // Initialize components
        KubePathGraph.init();
        KubePathControls.init();

        // Detail panel close
        document.getElementById('btn-close-detail')?.addEventListener('click', () => {
            this.hideDetailPanel();
        });

        // Check health
        await this.checkHealth();

        // Try to load existing graph
        await this.refreshGraph();
    },

    /**
     * Check Neo4j health status.
     */
    async checkHealth() {
        const statusDot = document.querySelector('#neo4j-status .status-dot');
        try {
            const health = await KubePathAPI.health();
            if (health.neo4j_connected) {
                statusDot?.classList.add('connected');
                statusDot?.classList.remove('disconnected');
            } else {
                statusDot?.classList.add('disconnected');
                statusDot?.classList.remove('connected');
            }
        } catch {
            statusDot?.classList.add('disconnected');
            statusDot?.classList.remove('connected');
        }
    },

    /**
     * Refresh the graph from the backend.
     */
    async refreshGraph() {
        try {
            const graph = await KubePathAPI.getGraph();

            if (graph.total_nodes > 0) {
                KubePathGraph.loadData(graph);
                this.state.graphLoaded = true;
                document.getElementById('empty-state')?.classList.add('hidden');
            } else {
                document.getElementById('empty-state')?.classList.remove('hidden');
                this.state.graphLoaded = false;
            }

            // Update header stats
            this._updateStats(graph);

            // Build filter chips
            KubePathControls.buildFilterChips();

            // Update risk score
            await this._updateRiskScore();

        } catch (err) {
            console.warn('Failed to load graph:', err);
        }
    },

    /**
     * Show node detail panel.
     */
    async showNodeDetail(uid) {
        const panel = document.getElementById('detail-panel');
        const content = document.getElementById('detail-content');
        const title = document.getElementById('detail-title');
        if (!panel || !content) return;

        try {
            const detail = await KubePathAPI.getNodeDetail(uid);
            const node = detail.node || {};
            const neighbors = detail.neighbors || [];

            title.textContent = node.name || 'Node Details';
            this.state.selectedNode = uid;

            const riskClass = (node.risk_level || 'INFO').toLowerCase();
            const nodeColor = NODE_COLORS[node.node_type] || '#78909c';

            let html = `
                <div class="detail-section">
                    <h3>Properties</h3>
                    <div class="detail-row">
                        <span class="key">Type</span>
                        <span class="value" style="color:${nodeColor}">${node.node_type || '—'}</span>
                    </div>
                    <div class="detail-row">
                        <span class="key">Risk Level</span>
                        <span class="value"><span class="risk-badge ${riskClass}">${node.risk_level || 'INFO'}</span></span>
                    </div>
            `;

            // Show relevant properties
            const skipKeys = new Set(['uid', 'name', 'node_type', 'risk_level', 'label']);
            for (const [key, value] of Object.entries(node)) {
                if (skipKeys.has(key) || key.startsWith('prop_')) continue;
                if (value === null || value === undefined || value === '') continue;
                html += `
                    <div class="detail-row">
                        <span class="key">${this._formatKey(key)}</span>
                        <span class="value">${this._formatValue(value)}</span>
                    </div>
                `;
            }

            // Show prop_ properties
            for (const [key, value] of Object.entries(node)) {
                if (!key.startsWith('prop_')) continue;
                if (value === null || value === undefined || value === '') continue;
                const cleanKey = key.replace('prop_', '');
                html += `
                    <div class="detail-row">
                        <span class="key">${this._formatKey(cleanKey)}</span>
                        <span class="value">${this._formatValue(value)}</span>
                    </div>
                `;
            }
            html += '</div>';

            // Neighbors
            if (neighbors.length > 0) {
                html += '<div class="detail-section"><h3>Connections (' + neighbors.length + ')</h3>';
                for (const n of neighbors) {
                    const nNode = n.node || {};
                    const nRel = n.relationship || {};
                    const nColor = NODE_COLORS[nNode.node_type] || '#78909c';
                    const direction = n.direction || '';

                    html += `
                        <div class="neighbor-item" onclick="KubePathApp.showNodeDetail('${nNode.uid}')">
                            <span class="neighbor-dot" style="background:${nColor}"></span>
                            <div class="neighbor-info">
                                <div class="neighbor-name">${nNode.name || nNode.uid || '—'}</div>
                                <div class="neighbor-type">${nRel.relation_type || nNode.node_type || ''}</div>
                            </div>
                            <span class="neighbor-direction">${direction === 'outgoing' ? '→' : '←'}</span>
                        </div>
                    `;
                }
                html += '</div>';
            }

            content.innerHTML = html;
            panel.classList.remove('hidden');

        } catch (err) {
            this.showToast(`Failed to load node details: ${err.message}`, 'error');
        }
    },

    /**
     * Show edge detail.
     */
    showEdgeDetail(data) {
        const panel = document.getElementById('detail-panel');
        const content = document.getElementById('detail-content');
        const title = document.getElementById('detail-title');
        if (!panel || !content) return;

        title.textContent = 'Edge Details';

        const riskClass = (data.risk_level || 'INFO').toLowerCase();
        let html = `
            <div class="detail-section">
                <h3>Relationship</h3>
                <div class="detail-row">
                    <span class="key">Type</span>
                    <span class="value">${data.relation_type || data.label || '—'}</span>
                </div>
                <div class="detail-row">
                    <span class="key">Risk Level</span>
                    <span class="value"><span class="risk-badge ${riskClass}">${data.risk_level || 'INFO'}</span></span>
                </div>
        `;

        if (data.description) {
            html += `
                <div class="detail-row">
                    <span class="key">Description</span>
                    <span class="value">${data.description}</span>
                </div>
            `;
        }

        if (data.is_attack_edge) {
            html += `
                <div class="detail-row">
                    <span class="key">Attack Edge</span>
                    <span class="value"><span class="risk-badge high">Yes</span></span>
                </div>
            `;
        }
        html += '</div>';

        content.innerHTML = html;
        panel.classList.remove('hidden');
    },

    /**
     * Hide the detail panel.
     */
    hideDetailPanel() {
        document.getElementById('detail-panel')?.classList.add('hidden');
        this.state.selectedNode = null;
        KubePathGraph.clearHighlights();
    },

    // ── Loading ─────────────────────────────────────────────────

    showLoading(message = 'Loading...') {
        const overlay = document.getElementById('loading-overlay');
        const msg = document.getElementById('loading-message');
        if (overlay) overlay.classList.remove('hidden');
        if (msg) msg.textContent = message;
    },

    hideLoading() {
        document.getElementById('loading-overlay')?.classList.add('hidden');
    },

    // ── Toast Notifications ─────────────────────────────────────

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `<span class="toast-icon">${icons[type] || 'ℹ'}</span><span>${message}</span>`;

        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    },

    // ── Private ─────────────────────────────────────────────────

    _updateStats(graph) {
        const nodeCount = document.querySelector('#node-count-display .status-value');
        const edgeCount = document.querySelector('#edge-count-display .status-value');
        if (nodeCount) nodeCount.textContent = graph.total_nodes || 0;
        if (edgeCount) edgeCount.textContent = graph.total_edges || 0;
    },

    async _updateRiskScore() {
        try {
            const score = await KubePathAPI.getRiskScore();
            const scoreText = document.getElementById('score-text');
            const scoreGrade = document.getElementById('score-grade');
            const scoreRing = document.getElementById('score-ring-fill');

            if (scoreText) scoreText.textContent = Math.round(score.score);
            if (scoreGrade) {
                scoreGrade.textContent = score.grade;
                // Color the grade based on risk
                const gradeColors = { A: '#00e676', B: '#00e676', C: '#ffea00', D: '#ff9100', F: '#ff1744' };
                scoreGrade.style.color = gradeColors[score.grade] || '#94a3b8';
            }

            // Animate ring
            if (scoreRing) {
                const circumference = 2 * Math.PI * 18; // r=18
                const offset = circumference - (score.score / 100) * circumference;
                scoreRing.style.strokeDashoffset = offset;

                // Color ring based on score
                if (score.score >= 80) scoreRing.style.stroke = '#ff1744';
                else if (score.score >= 60) scoreRing.style.stroke = '#ff9100';
                else if (score.score >= 40) scoreRing.style.stroke = '#ffea00';
                else if (score.score >= 20) scoreRing.style.stroke = '#00e676';
                else scoreRing.style.stroke = '#00f5d4';
            }
        } catch (err) {
            console.warn('Failed to update risk score:', err);
        }
    },

    _formatKey(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    },

    _formatValue(value) {
        if (typeof value === 'boolean') {
            return value
                ? '<span style="color:#00e676">✓ Yes</span>'
                : '<span style="color:#64748b">✗ No</span>';
        }
        if (typeof value === 'number') return value.toString();
        if (typeof value === 'string' && value.length > 60) {
            return value.substring(0, 57) + '…';
        }
        return String(value);
    },
};

// ── Bootstrap ───────────────────────────────────────────────────

window.KubePathApp = KubePathApp;

document.addEventListener('DOMContentLoaded', () => {
    KubePathApp.init();
});
