/**
 * KubePath UI Controls
 * Manages sidebar panels, filters, and user interactions.
 */

const KubePathControls = {
    activeFilters: {
        nodeTypes: [],
        riskLevels: [],
        namespace: '',
        search: '',
        attackEdgesOnly: false,
    },

    /**
     * Initialize all control handlers.
     */
    init() {
        this._initPanelToggles();
        this._initIngestionControls();
        this._initFilterControls();
        this._initAnalysisControls();
        this._initLayoutControls();
        this._initModalControls();
    },

    // ── Panel Toggle ────────────────────────────────────────────

    _initPanelToggles() {
        document.querySelectorAll('.panel-header[data-toggle]').forEach(header => {
            header.addEventListener('click', () => {
                const targetId = header.getAttribute('data-toggle');
                const content = document.getElementById(targetId);
                if (content) {
                    content.classList.toggle('collapsed');
                    header.classList.toggle('collapsed');
                }
            });
        });
    },

    // ── Ingestion Controls ──────────────────────────────────────

    _initIngestionControls() {
        // Ingest K8s
        document.getElementById('btn-ingest-k8s')?.addEventListener('click', async () => {
            KubePathApp.showLoading('Ingesting Kubernetes cluster...');
            try {
                const result = await KubePathAPI.ingestKubernetes();
                if (result.success) {
                    KubePathApp.showToast('Kubernetes cluster ingested successfully', 'success');
                    await KubePathApp.refreshGraph();
                } else {
                    KubePathApp.showToast(`Ingestion failed: ${result.error}`, 'error');
                }
            } catch (err) {
                KubePathApp.showToast(`Error: ${err.message}`, 'error');
            }
            KubePathApp.hideLoading();
        });

        // Ingest AWS
        document.getElementById('btn-ingest-aws')?.addEventListener('click', async () => {
            KubePathApp.showLoading('Ingesting AWS IAM...');
            try {
                const result = await KubePathAPI.ingestAWS();
                if (result.success) {
                    KubePathApp.showToast('AWS IAM ingested successfully', 'success');
                    await KubePathApp.refreshGraph();
                } else {
                    KubePathApp.showToast(`Ingestion failed: ${result.error}`, 'error');
                }
            } catch (err) {
                KubePathApp.showToast(`Error: ${err.message}`, 'error');
            }
            KubePathApp.hideLoading();
        });

        // Upload file
        const fileInput = document.getElementById('file-input');
        document.getElementById('btn-upload')?.addEventListener('click', () => {
            fileInput?.click();
        });

        fileInput?.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const sourceType = document.getElementById('upload-type')?.value || 'kubernetes';
            KubePathApp.showLoading(`Uploading ${file.name}...`);

            try {
                const result = await KubePathAPI.uploadFile(sourceType, file);
                if (result.success) {
                    KubePathApp.showToast(`Config uploaded: ${JSON.stringify(result.stats)}`, 'success');
                    await KubePathApp.refreshGraph();
                } else {
                    KubePathApp.showToast(`Upload failed: ${result.error}`, 'error');
                }
            } catch (err) {
                KubePathApp.showToast(`Error: ${err.message}`, 'error');
            }

            fileInput.value = '';
            KubePathApp.hideLoading();
        });

        // Clear graph
        document.getElementById('btn-clear')?.addEventListener('click', async () => {
            if (!confirm('Clear the entire attack graph? This cannot be undone.')) return;
            KubePathApp.showLoading('Clearing graph...');
            try {
                await KubePathAPI.clearGraph();
                KubePathApp.showToast('Graph cleared', 'info');
                await KubePathApp.refreshGraph();
            } catch (err) {
                KubePathApp.showToast(`Error: ${err.message}`, 'error');
            }
            KubePathApp.hideLoading();
        });
    },

    // ── Filter Controls ─────────────────────────────────────────

    _initFilterControls() {
        // Search
        const searchInput = document.getElementById('search-input');
        let searchTimeout;
        searchInput?.addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                this.activeFilters.search = searchInput.value;
                this._applyFilters();
            }, 300);
        });

        // Reset filters
        document.getElementById('btn-reset-filters')?.addEventListener('click', () => {
            this.activeFilters = { nodeTypes: [], riskLevels: [], namespace: '', search: '', attackEdgesOnly: false };
            searchInput.value = '';
            document.getElementById('namespace-filter').value = '';
            this._rebuildFilterChips();
            KubePathGraph.resetFilters();
        });

        // Attack edges only
        document.getElementById('btn-show-attack-edges')?.addEventListener('click', () => {
            this.activeFilters.attackEdgesOnly = !this.activeFilters.attackEdgesOnly;
            const btn = document.getElementById('btn-show-attack-edges');
            btn.classList.toggle('active');
            if (this.activeFilters.attackEdgesOnly) {
                btn.style.background = 'rgba(123, 97, 255, 0.15)';
                btn.style.color = '#7b61ff';
                btn.style.borderColor = '#7b61ff';
            } else {
                btn.style.background = '';
                btn.style.color = '';
                btn.style.borderColor = '';
            }
            this._applyFilters();
        });

        // Namespace filter
        document.getElementById('namespace-filter')?.addEventListener('change', (e) => {
            this.activeFilters.namespace = e.target.value;
            this._applyFilters();
        });
    },

    /**
     * Build filter chips for node types and risk levels based on current graph data.
     */
    buildFilterChips() {
        this._rebuildFilterChips();
    },

    _rebuildFilterChips() {
        // Node type chips
        const nodeTypeContainer = document.getElementById('node-type-filters');
        if (nodeTypeContainer) {
            nodeTypeContainer.innerHTML = '';
            const types = KubePathGraph.getNodeTypes();
            for (const t of types) {
                const chip = document.createElement('span');
                chip.className = 'chip';
                chip.innerHTML = `<span class="chip-dot" style="background:${NODE_COLORS[t] || '#78909c'}"></span>${t}`;
                chip.addEventListener('click', () => {
                    chip.classList.toggle('active');
                    if (chip.classList.contains('active')) {
                        this.activeFilters.nodeTypes.push(t);
                    } else {
                        this.activeFilters.nodeTypes = this.activeFilters.nodeTypes.filter(x => x !== t);
                    }
                    this._applyFilters();
                });
                // Restore active state
                if (this.activeFilters.nodeTypes.includes(t)) chip.classList.add('active');
                nodeTypeContainer.appendChild(chip);
            }
        }

        // Risk level chips
        const riskContainer = document.getElementById('risk-level-filters');
        if (riskContainer) {
            riskContainer.innerHTML = '';
            const risks = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
            for (const r of risks) {
                const chip = document.createElement('span');
                chip.className = 'chip';
                chip.innerHTML = `<span class="chip-dot" style="background:${RISK_COLORS[r]}"></span>${r}`;
                chip.addEventListener('click', () => {
                    chip.classList.toggle('active');
                    if (chip.classList.contains('active')) {
                        this.activeFilters.riskLevels.push(r);
                    } else {
                        this.activeFilters.riskLevels = this.activeFilters.riskLevels.filter(x => x !== r);
                    }
                    this._applyFilters();
                });
                if (this.activeFilters.riskLevels.includes(r)) chip.classList.add('active');
                riskContainer.appendChild(chip);
            }
        }

        // Namespace dropdown
        const nsSelect = document.getElementById('namespace-filter');
        if (nsSelect) {
            const currentVal = nsSelect.value;
            nsSelect.innerHTML = '<option value="">All Namespaces</option>';
            const namespaces = KubePathGraph.getNamespaces();
            for (const ns of namespaces) {
                const opt = document.createElement('option');
                opt.value = ns;
                opt.textContent = ns;
                nsSelect.appendChild(opt);
            }
            nsSelect.value = currentVal;
        }
    },

    _applyFilters() {
        KubePathGraph.applyFilters(this.activeFilters);
    },

    // ── Analysis Controls ───────────────────────────────────────

    _initAnalysisControls() {
        // Find attack paths
        document.getElementById('btn-find-paths')?.addEventListener('click', async () => {
            KubePathApp.showLoading('Analyzing attack paths...');
            try {
                const result = await KubePathAPI.getAttackPaths();
                this._renderAttackPaths(result.paths || []);
                KubePathApp.showToast(`Found ${result.total_paths} attack paths`, 'info');
                document.getElementById('paths-count-display').querySelector('.status-value').textContent = result.total_paths;
            } catch (err) {
                KubePathApp.showToast(`Error: ${err.message}`, 'error');
            }
            KubePathApp.hideLoading();
        });

        // Critical nodes
        document.getElementById('btn-critical-nodes')?.addEventListener('click', async () => {
            try {
                const result = await KubePathAPI.getCriticalNodes();
                const nodes = result.nodes || [];
                if (nodes.length === 0) {
                    KubePathApp.showToast('No critical chokepoints found', 'info');
                    return;
                }
                const uids = nodes.map(n => n.uid);
                KubePathGraph.highlightNodes(uids);
                KubePathApp.showToast(`Highlighted ${nodes.length} chokepoint nodes`, 'success');
            } catch (err) {
                KubePathApp.showToast(`Error: ${err.message}`, 'error');
            }
        });

        // Entry points
        document.getElementById('btn-entry-points')?.addEventListener('click', async () => {
            try {
                const result = await KubePathAPI.getEntryPoints();
                const entries = result.entry_points || [];
                if (entries.length === 0) {
                    KubePathApp.showToast('No external entry points found', 'info');
                    return;
                }
                const uids = entries.map(e => e.uid);
                KubePathGraph.highlightNodes(uids);
                KubePathApp.showToast(`Highlighted ${entries.length} entry points`, 'success');
            } catch (err) {
                KubePathApp.showToast(`Error: ${err.message}`, 'error');
            }
        });

        // Findings
        document.getElementById('btn-findings')?.addEventListener('click', async () => {
            try {
                const result = await KubePathAPI.getFindings();
                this._renderFindings(result.findings || []);
                document.getElementById('findings-modal')?.classList.remove('hidden');
            } catch (err) {
                KubePathApp.showToast(`Error: ${err.message}`, 'error');
            }
        });
    },

    _renderAttackPaths(paths) {
        const container = document.getElementById('attack-paths-list');
        if (!container) return;
        container.innerHTML = '';

        if (paths.length === 0) {
            container.innerHTML = '<div class="result-card"><div class="result-card-body">No attack paths found</div></div>';
            return;
        }

        for (const [i, path] of paths.entries()) {
            const card = document.createElement('div');
            card.className = 'result-card';

            const riskClass = (path.risk_level || 'INFO').toLowerCase();
            const source = path.source || {};
            const target = path.target || {};
            const hops = path.hops || '?';
            const score = path.score?.toFixed(0) || '0';

            card.innerHTML = `
                <div class="result-card-header">
                    <span class="result-card-title">#${i + 1} — ${hops} hops</span>
                    <span class="risk-badge ${riskClass}">${path.risk_level || 'INFO'}</span>
                </div>
                <div class="result-card-body">
                    <strong>${source.name || '?'}</strong> → <strong>${target.name || '?'}</strong>
                    <br>Score: ${score}/100
                </div>
            `;

            card.addEventListener('click', () => {
                // Highlight this path
                container.querySelectorAll('.result-card').forEach(c => c.classList.remove('active'));
                card.classList.add('active');

                const nodeUids = (path.nodes || []).map(n => n.uid);
                KubePathGraph.highlightPath(nodeUids, path.relationships || []);
            });

            container.appendChild(card);
        }
    },

    _renderFindings(findings) {
        const container = document.getElementById('findings-list');
        if (!container) return;
        container.innerHTML = '';

        if (findings.length === 0) {
            container.innerHTML = '<p style="color:var(--text-muted);text-align:center">No findings detected</p>';
            return;
        }

        for (const finding of findings) {
            const riskClass = (finding.risk_level || 'INFO').toLowerCase();
            const card = document.createElement('div');
            card.className = 'finding-card';
            card.innerHTML = `
                <div class="finding-card-header">
                    <span class="finding-title">${finding.title}</span>
                    <div style="display:flex;gap:6px;align-items:center">
                        <span class="finding-category">${finding.category}</span>
                        <span class="risk-badge ${riskClass}">${finding.risk_level}</span>
                    </div>
                </div>
                <div class="finding-description">${finding.description}</div>
                <div class="finding-resources">
                    ${(finding.affected_resources || []).map(r => `<span class="finding-resource">${r}</span>`).join('')}
                </div>
                ${finding.remediation ? `<div class="finding-remediation">💡 ${finding.remediation}</div>` : ''}
            `;
            container.appendChild(card);
        }
    },

    // ── Layout Controls ─────────────────────────────────────────

    _initLayoutControls() {
        const layoutMap = {
            'btn-layout-cose': 'cose-bilkent',
            'btn-layout-circle': 'circle',
            'btn-layout-grid': 'grid',
            'btn-layout-breadthfirst': 'breadthfirst',
        };

        for (const [btnId, layoutName] of Object.entries(layoutMap)) {
            document.getElementById(btnId)?.addEventListener('click', () => {
                KubePathGraph.runLayout(layoutName);
            });
        }

        document.getElementById('btn-fit')?.addEventListener('click', () => KubePathGraph.fit());
        document.getElementById('btn-export-png')?.addEventListener('click', () => KubePathGraph.exportPNG());
        document.getElementById('btn-export-json')?.addEventListener('click', () => KubePathGraph.exportJSON());

        // Edge labels toggle
        document.getElementById('toggle-edge-labels')?.addEventListener('change', (e) => {
            KubePathGraph.setEdgeLabels(e.target.checked);
        });
    },

    // ── Modal Controls ──────────────────────────────────────────

    _initModalControls() {
        document.getElementById('btn-close-findings')?.addEventListener('click', () => {
            document.getElementById('findings-modal')?.classList.add('hidden');
        });
        document.querySelector('#findings-modal .modal-backdrop')?.addEventListener('click', () => {
            document.getElementById('findings-modal')?.classList.add('hidden');
        });
    },
};
