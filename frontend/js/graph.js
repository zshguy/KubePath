/**
 * KubePath Graph Visualization
 * Cytoscape.js-based interactive attack graph renderer.
 */

// Node type colors
const NODE_COLORS = {
    Pod: '#42a5f5',
    ServiceAccount: '#ab47bc',
    Role: '#66bb6a',
    ClusterRole: '#ef5350',
    RoleBinding: '#78909c',
    ClusterRoleBinding: '#e57373',
    Namespace: '#5c6bc0',
    Node: '#8d6e63',
    Secret: '#ffa726',
    Service: '#26c6da',
    IAMUser: '#7e57c2',
    IAMRole: '#ec407a',
    IAMPolicy: '#26a69a',
    IAMGroup: '#9ccc65',
    ClusterAdmin: '#ff1744',
    Internet: '#bdbdbd',
    External: '#90a4ae',
    Container: '#29b6f6',
    EC2Instance: '#ff7043',
    LambdaFunction: '#ffca28',
};

// Node type shapes
const NODE_SHAPES = {
    Pod: 'hexagon',
    ServiceAccount: 'diamond',
    Role: 'round-rectangle',
    ClusterRole: 'round-rectangle',
    RoleBinding: 'round-triangle',
    ClusterRoleBinding: 'round-triangle',
    Namespace: 'barrel',
    Node: 'rectangle',
    Secret: 'tag',
    Service: 'round-pentagon',
    IAMUser: 'ellipse',
    IAMRole: 'diamond',
    IAMPolicy: 'round-rectangle',
    IAMGroup: 'barrel',
    ClusterAdmin: 'star',
    Internet: 'ellipse',
    External: 'ellipse',
};

// Risk level colors
const RISK_COLORS = {
    CRITICAL: '#ff1744',
    HIGH: '#ff9100',
    MEDIUM: '#ffea00',
    LOW: '#00e676',
    INFO: '#448aff',
};

const KubePathGraph = {
    cy: null,
    highlightedPaths: [],

    /**
     * Initialize the Cytoscape.js graph.
     */
    init() {
        this.cy = cytoscape({
            container: document.getElementById('cy'),
            elements: [],
            style: this._getStylesheet(),
            layout: { name: 'preset' },
            minZoom: 0.1,
            maxZoom: 5,
            wheelSensitivity: 0.3,
            boxSelectionEnabled: true,
            selectionType: 'single',
        });

        // Event handlers
        this.cy.on('tap', 'node', (e) => {
            const node = e.target;
            this._onNodeClick(node);
        });

        this.cy.on('tap', 'edge', (e) => {
            const edge = e.target;
            this._onEdgeClick(edge);
        });

        this.cy.on('tap', (e) => {
            if (e.target === this.cy) {
                this.clearHighlights();
            }
        });

        // Hover effects
        this.cy.on('mouseover', 'node', (e) => {
            const node = e.target;
            node.addClass('hover');
            document.body.style.cursor = 'pointer';
        });

        this.cy.on('mouseout', 'node', (e) => {
            e.target.removeClass('hover');
            document.body.style.cursor = 'default';
        });

        this.cy.on('mouseover', 'edge', () => {
            document.body.style.cursor = 'pointer';
        });

        this.cy.on('mouseout', 'edge', () => {
            document.body.style.cursor = 'default';
        });
    },

    /**
     * Load graph data from the API response.
     */
    loadData(graphData) {
        if (!this.cy) this.init();

        this.cy.elements().remove();

        if (!graphData.nodes?.length) return;

        // Add nodes
        const elements = [];
        for (const n of graphData.nodes) {
            elements.push({
                group: 'nodes',
                data: {
                    ...n.data,
                    id: n.data.id,
                    label: this._truncateLabel(n.data.label || n.data.name || n.data.id),
                    fullLabel: n.data.label || n.data.name || n.data.id,
                },
            });
        }

        // Add edges
        for (const e of graphData.edges) {
            elements.push({
                group: 'edges',
                data: {
                    ...e.data,
                    id: e.data.id,
                    source: e.data.source,
                    target: e.data.target,
                },
            });
        }

        this.cy.add(elements);
        this.runLayout('cose-bilkent');

        // Show/hide empty state
        const emptyState = document.getElementById('empty-state');
        if (emptyState) {
            emptyState.classList.toggle('hidden', graphData.nodes.length > 0);
        }
    },

    /**
     * Run a layout algorithm.
     */
    runLayout(name) {
        if (!this.cy || this.cy.nodes().length === 0) return;

        const layouts = {
            'cose-bilkent': {
                name: 'cose-bilkent',
                animate: 'end',
                animationDuration: 800,
                nodeRepulsion: 8000,
                idealEdgeLength: 120,
                edgeElasticity: 0.1,
                nestingFactor: 0.1,
                gravity: 0.2,
                numIter: 2500,
                tile: true,
                randomize: true,
                fit: true,
                padding: 40,
                nodeDimensionsIncludeLabels: true,
            },
            cose: {
                name: 'cose',
                animate: true,
                animationDuration: 500,
                nodeRepulsion: () => 6000,
                idealEdgeLength: () => 100,
                fit: true,
                padding: 40,
                nodeDimensionsIncludeLabels: true,
                randomize: false,
            },
            circle: {
                name: 'circle',
                animate: true,
                animationDuration: 500,
                fit: true,
                padding: 40,
            },
            grid: {
                name: 'grid',
                animate: true,
                animationDuration: 500,
                fit: true,
                padding: 40,
                condense: true,
            },
            breadthfirst: {
                name: 'breadthfirst',
                animate: true,
                animationDuration: 500,
                fit: true,
                padding: 40,
                directed: true,
                spacingFactor: 1.5,
            },
        };

        const config = layouts[name] || layouts['cose-bilkent'];
        this.cy.layout(config).run();
    },

    /**
     * Highlight specific nodes and edges (e.g., attack paths).
     */
    highlightPath(nodeUids, edgeData) {
        this.clearHighlights();

        // Dim all nodes
        this.cy.elements().addClass('dimmed');

        // Highlight path nodes
        for (const uid of nodeUids) {
            const node = this.cy.getElementById(uid);
            if (node.length) {
                node.removeClass('dimmed').addClass('highlighted');
            }
        }

        // Highlight path edges
        if (edgeData) {
            for (const ed of edgeData) {
                const source = ed.source;
                const target = ed.target;
                const edges = this.cy.edges(`[source = "${source}"][target = "${target}"]`);
                edges.forEach(edge => {
                    edge.removeClass('dimmed').addClass('attack-path');
                });
            }
        }
    },

    /**
     * Highlight nodes by UIDs.
     */
    highlightNodes(uids) {
        this.clearHighlights();
        this.cy.elements().addClass('dimmed');
        for (const uid of uids) {
            const node = this.cy.getElementById(uid);
            if (node.length) {
                node.removeClass('dimmed').addClass('highlighted');
            }
        }
    },

    /**
     * Clear all highlights.
     */
    clearHighlights() {
        if (!this.cy) return;
        this.cy.elements().removeClass('dimmed highlighted attack-path hover');
    },

    /**
     * Filter visible nodes.
     */
    applyFilters(filters) {
        if (!this.cy) return;

        this.cy.nodes().forEach(node => {
            const data = node.data();
            let visible = true;

            // Node type filter
            if (filters.nodeTypes && filters.nodeTypes.length > 0) {
                if (!filters.nodeTypes.includes(data.node_type)) {
                    visible = false;
                }
            }

            // Risk level filter
            if (filters.riskLevels && filters.riskLevels.length > 0) {
                if (!filters.riskLevels.includes(data.risk_level)) {
                    visible = false;
                }
            }

            // Namespace filter
            if (filters.namespace) {
                if (data.namespace && data.namespace !== filters.namespace) {
                    visible = false;
                }
            }

            // Search filter
            if (filters.search) {
                const search = filters.search.toLowerCase();
                const label = (data.label || data.name || '').toLowerCase();
                const nodeType = (data.node_type || '').toLowerCase();
                if (!label.includes(search) && !nodeType.includes(search)) {
                    visible = false;
                }
            }

            // Attack edges only
            if (filters.attackEdgesOnly) {
                // Show node only if it has at least one attack edge
                const hasAttackEdge = node.connectedEdges().some(e =>
                    e.data('is_attack_edge') === true || e.data('is_attack_edge') === 'true'
                );
                if (!hasAttackEdge) visible = false;
            }

            if (visible) {
                node.style('display', 'element');
            } else {
                node.style('display', 'none');
            }
        });

        // Hide edges where either endpoint is hidden
        this.cy.edges().forEach(edge => {
            const srcVisible = edge.source().style('display') !== 'none';
            const tgtVisible = edge.target().style('display') !== 'none';
            edge.style('display', (srcVisible && tgtVisible) ? 'element' : 'none');
        });
    },

    /**
     * Reset all filters.
     */
    resetFilters() {
        if (!this.cy) return;
        this.cy.elements().style('display', 'element');
        this.clearHighlights();
    },

    /**
     * Toggle edge labels visibility.
     */
    setEdgeLabels(visible) {
        if (!this.cy) return;
        this.cy.edges().style('label', visible ? (e) => e.data('label') || '' : '');
    },

    /**
     * Fit view to all visible elements.
     */
    fit() {
        if (!this.cy) return;
        this.cy.fit(undefined, 40);
    },

    /**
     * Export graph as PNG.
     */
    exportPNG() {
        if (!this.cy) return;
        const png = this.cy.png({ output: 'blob', bg: '#0a0e17', full: true, scale: 2 });                
        const url = URL.createObjectURL(png);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'kubepath-attack-graph.png';
        a.click();
        URL.revokeObjectURL(url);
    },

    /**
     * Export graph as JSON.
     */
    exportJSON() {
        if (!this.cy) return;
        const json = this.cy.json();
        const blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'kubepath-graph.json';
        a.click();
        URL.revokeObjectURL(url);
    },

    /**
     * Get all unique node types in the current graph.
     */
    getNodeTypes() {
        if (!this.cy) return [];
        const types = new Set();
        this.cy.nodes().forEach(n => {
            const t = n.data('node_type');
            if (t) types.add(t);
        });
        return Array.from(types).sort();
    },

    /**
     * Get all unique namespaces in the current graph.
     */
    getNamespaces() {
        if (!this.cy) return [];
        const ns = new Set();
        this.cy.nodes().forEach(n => {
            const namespace = n.data('namespace');
            if (namespace) ns.add(namespace);
        });
        return Array.from(ns).sort();
    },

    // ── Private Methods ──────────────────────────────────────────

    _onNodeClick(node) {
        const data = node.data();
        if (window.KubePathApp) {
            window.KubePathApp.showNodeDetail(data.id);
        }
    },

    _onEdgeClick(edge) {
        const data = edge.data();
        if (window.KubePathApp) {
            window.KubePathApp.showEdgeDetail(data);
        }
    },

    _truncateLabel(label) {
        if (!label) return '?';
        // For namespaced names, show just the resource name
        if (label.includes('/')) {
            const parts = label.split('/');
            label = parts[parts.length - 1];
        }
        return label.length > 20 ? label.substring(0, 18) + '…' : label;
    },

    _getStylesheet() {
        return [
            // ── Node base style ──
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'text-margin-y': 6,
                    'font-family': 'Inter, sans-serif',
                    'font-size': '9px',
                    'font-weight': 500,
                    'color': '#94a3b8',
                    'text-outline-color': '#0a0e17',
                    'text-outline-width': 2,
                    'text-max-width': '100px',
                    'text-wrap': 'ellipsis',
                    'width': 36,
                    'height': 36,
                    'background-color': (n) => NODE_COLORS[n.data('node_type')] || '#78909c',
                    'shape': (n) => NODE_SHAPES[n.data('node_type')] || 'ellipse',
                    'border-width': 2,
                    'border-color': (n) => {
                        const risk = n.data('risk_level');
                        return RISK_COLORS[risk] || 'rgba(255,255,255,0.1)';
                    },
                    'border-opacity': 0.6,
                    'background-opacity': 0.85,
                    'transition-property': 'width, height, border-width, border-color, background-opacity, opacity',
                    'transition-duration': '200ms',
                },
            },
            // ── ClusterAdmin node (larger, glowing) ──
            {
                selector: 'node[node_type = "ClusterAdmin"]',
                style: {
                    'width': 52,
                    'height': 52,
                    'font-size': '11px',
                    'font-weight': 700,
                    'border-width': 3,
                    'border-color': '#ff1744',
                    'background-opacity': 1,
                    'color': '#ff1744',
                },
            },
            // ── Internet/External nodes ──
            {
                selector: 'node[node_type = "Internet"], node[node_type = "External"]',
                style: {
                    'width': 44,
                    'height': 44,
                    'border-style': 'dashed',
                    'border-width': 2,
                },
            },
            // ── Node hover ──
            {
                selector: 'node.hover',
                style: {
                    'width': 44,
                    'height': 44,
                    'border-width': 3,
                    'background-opacity': 1,
                    'z-index': 999,
                },
            },
            // ── Highlighted node ──
            {
                selector: 'node.highlighted',
                style: {
                    'width': 48,
                    'height': 48,
                    'border-width': 3,
                    'border-color': '#00f5d4',
                    'background-opacity': 1,
                    'z-index': 999,
                    'color': '#e2e8f0',
                    'font-weight': 700,
                    'font-size': '10px',
                },
            },
            // ── Dimmed node ──
            {
                selector: 'node.dimmed',
                style: {
                    'opacity': 0.15,
                },
            },
            // ── Edge base style ──
            {
                selector: 'edge',
                style: {
                    'width': 1.5,
                    'line-color': 'rgba(100, 116, 139, 0.4)',
                    'target-arrow-color': 'rgba(100, 116, 139, 0.4)',
                    'target-arrow-shape': 'triangle',
                    'arrow-scale': 0.8,
                    'curve-style': 'bezier',
                    'label': (e) => e.data('label') || '',
                    'font-family': 'JetBrains Mono, monospace',
                    'font-size': '7px',
                    'color': 'rgba(148, 163, 184, 0.5)',
                    'text-rotation': 'autorotate',
                    'text-margin-y': -8,
                    'text-outline-color': '#0a0e17',
                    'text-outline-width': 2,
                    'transition-property': 'line-color, width, opacity',
                    'transition-duration': '200ms',
                },
            },
            // ── Attack edges ──
            {
                selector: 'edge[is_attack_edge = "true"], edge[?is_attack_edge]',
                style: {
                    'width': 2,
                    'line-color': (e) => {
                        const risk = e.data('risk_level');
                        return RISK_COLORS[risk] || '#ff9100';
                    },
                    'target-arrow-color': (e) => {
                        const risk = e.data('risk_level');
                        return RISK_COLORS[risk] || '#ff9100';
                    },
                    'line-style': 'solid',
                    'color': 'rgba(255, 255, 255, 0.5)',
                },
            },
            // ── Highlighted attack path edges ──
            {
                selector: 'edge.attack-path',
                style: {
                    'width': 4,
                    'line-color': '#ff1744',
                    'target-arrow-color': '#ff1744',
                    'z-index': 999,
                    'color': '#ff1744',
                    'font-size': '8px',
                    'opacity': 1,
                },
            },
            // ── Dimmed edge ──
            {
                selector: 'edge.dimmed',
                style: {
                    'opacity': 0.08,
                },
            },
        ];
    },
};
