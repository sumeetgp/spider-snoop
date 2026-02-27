function toggleMobileMenu() {
    document.getElementById('mobileMenu').classList.toggle('hidden');
}

// --- State Management ---
let currentTrack = 'sentinel';
// Auth token is now handled via HttpOnly Cookie
let currentScanResult = null;

// Initial Auth Check (If cookie is missing/expired, API calls will fail -> Redirect)
// We defer this check to setupAuth() to avoid flash of content or double redirect loop


// --- Init ---
// Utility: Escape HTML to prevent XSS
function escapeHtml(text) {
    if (!text) return text;
    if (typeof text !== 'string') text = String(text);
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

document.addEventListener('DOMContentLoaded', () => {
    initParticles();
    setupAuth();
    showTrack('sentinel'); // Default

    // --- EVENT LISTENERS (CSP FIX) ---

    // Header
    const logo = document.getElementById('headerLogo');
    if (logo) logo.addEventListener('click', () => window.location.href = '/');

    const btnShowArchiveDesktop = document.getElementById('btnShowArchiveDesktop');
    if (btnShowArchiveDesktop) btnShowArchiveDesktop.addEventListener('click', showArchive);

    // Mobile Menu
    const btnMobileMenuToggle = document.getElementById('btnMobileMenuToggle');
    if (btnMobileMenuToggle) btnMobileMenuToggle.addEventListener('click', toggleMobileMenu);

    const btnMobileMenuClose = document.getElementById('btnMobileMenuClose');
    if (btnMobileMenuClose) btnMobileMenuClose.addEventListener('click', toggleMobileMenu);

    // Mobile Tracks
    const mobSentinel = document.getElementById('btnMobileTrackSentinel');
    if (mobSentinel) mobSentinel.addEventListener('click', () => { showTrack('sentinel'); toggleMobileMenu(); });

    const mobGuardian = document.getElementById('btnMobileTrackGuardian');
    if (mobGuardian) mobGuardian.addEventListener('click', () => { showTrack('guardian'); toggleMobileMenu(); });

    const mobSecurity = document.getElementById('btnMobileTrackSecurity');
    if (mobSecurity) mobSecurity.addEventListener('click', () => { showTrack('security'); toggleMobileMenu(); });

    const mobVision = document.getElementById('btnMobileTrackVision');
    if (mobVision) mobVision.addEventListener('click', () => { showTrack('vision'); toggleMobileMenu(); });

    const mobReports = document.getElementById('btnMobileReports');
    if (mobReports) mobReports.addEventListener('click', () => { showArchive(); toggleMobileMenu(); });

    const mobLogout = document.getElementById('btnMobileLogout');
    if (mobLogout) mobLogout.addEventListener('click', logout);


    // Sidebar Nav
    document.getElementById('nav-sentinel').addEventListener('click', () => showTrack('sentinel'));
    document.getElementById('nav-guardian').addEventListener('click', () => showTrack('guardian'));
    document.getElementById('nav-vision').addEventListener('click', () => showTrack('vision'));
    document.getElementById('nav-vision').addEventListener('click', () => showTrack('vision'));
    document.getElementById('nav-security').addEventListener('click', () => showTrack('security'));
    document.getElementById('nav-firewall').addEventListener('click', () => showFirewall());
    const navMetricsBtn = document.getElementById('nav-metrics');
    if (navMetricsBtn) navMetricsBtn.addEventListener('click', () => showMetrics());

    // Refresh Logic
    const btnRefreshFirewall = document.getElementById('btnRefreshFirewall');
    if (btnRefreshFirewall) btnRefreshFirewall.addEventListener('click', fetchFirewallStats);

    const sidebarLogout = document.getElementById('btnSidebarLogout');
    if (sidebarLogout) sidebarLogout.addEventListener('click', logout);

    // Main UI
    const inputZone = document.getElementById('inputZone');
    if (inputZone) inputZone.addEventListener('click', () => {
        if (currentTrack === 'vision') document.getElementById('videoInput').click();
        else document.getElementById('fileInput').click();
    });

    const btnCancelStaging = document.getElementById('btnCancelStaging');
    if (btnCancelStaging) btnCancelStaging.addEventListener('click', cancelStaging);

    const btnStartScan = document.getElementById('btnStartScan');
    if (btnStartScan) btnStartScan.addEventListener('click', startScan);

    const btnScanNext = document.getElementById('btnScanNext');
    if (btnScanNext) btnScanNext.addEventListener('click', () => showTrack(currentTrack));

    const btnCopyJSON = document.getElementById('btnCopyJSON');
    if (btnCopyJSON) btnCopyJSON.addEventListener('click', copyJSON);

    const btnRefreshArchive = document.getElementById('btnRefreshArchive');
    if (btnRefreshArchive) btnRefreshArchive.addEventListener('click', showArchive);

    // File Inputs
    const fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.addEventListener('change', () => handleFileSelection(fileInput));

    const videoInput = document.getElementById('videoInput');
    if (videoInput) videoInput.addEventListener('change', () => handleVideoSelection(videoInput));

    // User Management Events
    const navUsers = document.getElementById('nav-users');
    if (navUsers) navUsers.addEventListener('click', () => showUsers());

    const btnRefreshUsers = document.getElementById('btnRefreshUsers');
    if (btnRefreshUsers) btnRefreshUsers.addEventListener('click', fetchUsers);

    // Edit Modal Events
    const editForm = document.getElementById('editUserForm');
    if (editForm) editForm.addEventListener('submit', handleEditUserSubmit);

    const btnCloseEditUser = document.getElementById('btnCloseEditUser');
    if (btnCloseEditUser) btnCloseEditUser.addEventListener('click', closeEditUserModal);

    const btnCancelEdit = document.getElementById('btnCancelEdit');
    if (btnCancelEdit) btnCancelEdit.addEventListener('click', closeEditUserModal);
});

function copyJSON() {
    if (!currentScanResult) return;
    const json = JSON.stringify(currentScanResult, null, 2);
    navigator.clipboard.writeText(json).then(() => {
        const btn = document.getElementById('btnCopyJSON');
        const orig = btn.innerText;
        btn.innerText = "COPIED!";
        setTimeout(() => btn.innerText = orig, 1000);
    });
}

// --- Firewall View ---
async function showFirewall() {
    currentTrack = 'firewall';
    hideAllViews();
    document.getElementById('firewallView').classList.remove('hidden');
    setActiveNav('nav-firewall');

    // Update Header
    document.getElementById('trackTitle').innerHTML = `AI <span class="text-brand">FIREWALL</span>`;
    document.getElementById('trackDesc').innerText = "LLM Traffic Authorization & DLP Redaction";

    // Load Data
    await fetchFirewallStats();
}

async function fetchFirewallStats() {
    try {
        const res = await fetch('/api/dashboard/firewall-stats');
        if (!res.ok) throw new Error("Failed to fetch firewall stats");
        const data = await res.json();

        // Update Stats
        document.getElementById('stat-fw-total').innerText = data.stats.total_requests;
        document.getElementById('stat-fw-blocked').innerText = data.stats.blocked;
        document.getElementById('stat-fw-redacted').innerText = data.stats.redacted;
        document.getElementById('stat-fw-allowed').innerText = data.stats.allowed;

        // Update Table
        const tbody = document.getElementById('firewallTableBody');
        tbody.innerHTML = '';

        if (data.logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-500">No activity recorded yet</td></tr>`;
            return;
        }

        data.logs.forEach(log => {
            const tr = document.createElement('tr');
            tr.className = "hover:bg-white/5 transition";

            // Risk Badge
            let riskColor = "text-gray-400";
            if (log.risk_score === "CRITICAL") riskColor = "text-red-500 font-bold";
            else if (log.risk_score === "HIGH") riskColor = "text-orange-500 font-bold";
            else if (log.risk_score === "MEDIUM") riskColor = "text-yellow-500";

            // Action Badge
            let actionBadge = `<span class="px-2 py-1 rounded text-xs font-bold bg-gray-800 text-gray-300">${log.action}</span>`;
            if (log.action.includes("BLOCKED")) actionBadge = `<span class="px-2 py-1 rounded text-xs font-bold bg-red-900/30 text-red-500 border border-red-900/50">BLOCKED</span>`;
            else if (log.action === "REDACTED") actionBadge = `<span class="px-2 py-1 rounded text-xs font-bold bg-yellow-900/30 text-yellow-500 border border-yellow-900/50">REDACTED</span>`;
            else if (log.action === "ALLOWED") actionBadge = `<span class="px-2 py-1 rounded text-xs font-bold bg-green-900/30 text-green-500 border border-green-900/50">ALLOWED</span>`;

            tr.innerHTML = `
                <td class="p-4 text-xs text-gray-500">${new Date(log.timestamp).toLocaleTimeString()}</td>
                <td class="p-4 font-bold text-white">${log.user}</td>
                <td class="p-4 text-xs text-gray-400">${log.model}</td>
                <td class="p-4">${actionBadge}</td>
                <td class="p-4 text-xs ${riskColor}">${log.risk_score}</td>
                <td class="p-4 text-xs text-gray-500 truncate max-w-xs" title="${escapeHtml(log.summary)}">${escapeHtml(log.summary)}</td>
            `;
            tbody.appendChild(tr);
        });

    } catch (e) {
        console.error(e);
    }
}

// --- Onboarding Modal ---
// --- Onboarding Modal (Event Delegation) ---
// --- Onboarding Modal Global Handler ---
// --- Onboarding Modal Global Handler ---
// Logic moved to inline script in dashboard.html for CSP compliance fallback

// Event Delegation for Closing
document.addEventListener('click', (e) => {
    // Close (Button)
    if (e.target.closest('#btnCloseOnboarding') || e.target.closest('#btnDoneOnboarding')) {
        const modal = document.getElementById('onboardingModal');
        if (modal) modal.classList.add('hidden');
    }

    // Close (Backdrop)
    if (e.target.id === 'onboardingModal') {
        e.target.classList.add('hidden');
    }
});

function initParticles() {
    if (window.particlesJS) {
        particlesJS("bgCanvas", {
            "particles": {
                "number": { "value": 40, "density": { "enable": true, "value_area": 800 } },
                "color": { "value": "#88FFFF" },
                "shape": { "type": "circle" },
                "opacity": { "value": 0.3 },
                "size": { "value": 2 },
                "line_linked": { "enable": true, "distance": 150, "color": "#88FFFF", "opacity": 0.1, "width": 1 },
                "move": { "enable": true, "speed": 1 }
            },
            "retina_detect": true
        });
    }
}

async function setupAuth() {
    document.getElementById('authSection').classList.add('hidden');
    // We assume user might be logged in via cookie.
    // If /api/users/me fails, we redirect to login.

    try {
        // No need to manually add Authorization header
        const res = await fetch('/api/users/me');
        if (res.ok) {
            const user = await res.json();
            document.getElementById('userSection').classList.remove('hidden');
            document.getElementById('usernameDisplay').textContent = user.username.toUpperCase();

            // Show Admin Nav
            if (user.role === 'admin') {
                const navUsers = document.getElementById('nav-users');
                if (navUsers) navUsers.classList.remove('hidden');
                const navFirewall = document.getElementById('nav-firewall');
                if (navFirewall) navFirewall.classList.remove('hidden');
                const navMetrics = document.getElementById('nav-metrics');
                if (navMetrics) navMetrics.classList.remove('hidden');
            }

            // Enable Credits Widget
            const w = document.getElementById('creditsWidget');
            w.classList.remove('opacity-50', 'pointer-events-none');
            document.getElementById('creditsReset').textContent = "Resets in 60 mins";
            updateCredits(user.credits_remaining || 50); // Mock/Real
        } else {
            // Not authenticated
            window.location.replace('/login');
        }
    } catch (e) {
        console.error(e);
        window.location.replace('/login');
    }
}

async function logout() {
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {
        console.error("Logout failed", e);
    }
    window.location.href = '/';
}

function updateCredits(remaining) {
    const total = 50; // Assuming 50 is max
    const used = total - remaining;
    const percent = (used / total) * 100;

    const creditsBar = document.getElementById('creditsBar');
    const creditsText = document.getElementById('creditsText');

    if (creditsBar) creditsBar.style.width = `${percent}%`;
    if (creditsText) creditsText.innerText = `${used}/${total}`;

    // Update Mobile Widget
    const mBar = document.getElementById('mobileCreditsBar');
    const mText = document.getElementById('mobileCreditsText');
    if (mBar) mBar.style.width = `${percent}%`;
    if (mText) mText.innerText = `${used}/${total}`;

    if (percent >= 100) {
        // Optionally disable scan button or show message
    }
}

// --- Track Logic ---
const tracks = {
    'sentinel': {
        title: 'FILE GUARD',
        desc: 'Intelligent Malware & Virus Detection',
        req: 'SUPPORTED: All Files (MAX 50MB)',
        icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'
    },
    'guardian': {
        title: 'SECRET SCANNER',
        desc: 'PII, Secret Data (DLP) & Safe Wash',
        req: 'SUPPORTED: TXT, DOCX, XLSM, PDF, ZIP, PNG (MAX 10MB)',
        icon: 'M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z'
    },
    'vision': {
        title: 'VIDEO SCANNER',
        desc: 'Video & Audio Data Forensic',
        req: 'SUPPORTED: MP4, AVI, MKV, MP3, WAV (MAX 50MB)',
        icon: 'M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z'
    },
    'security': {
        title: 'CODE SECURITY',
        desc: 'Dependency & Secret Scanning (Supply Chain)',
        req: 'SUPPORTED: requirements.txt, package.json, .zip (MAX 50MB)',
        icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z'
    }
};

function showTrack(trackId) {
    currentTrack = trackId;

    // Handle Input Attributes (Dynamic Accept)
    const videoInput = document.getElementById('videoInput');
    const fileInput = document.getElementById('fileInput');

    if (trackId === 'vision') { // effectively omnisense
        videoInput.accept = ".mp4,.mov,.avi,.mkv,.webm,.mp3,.wav,.m4a,.flac";
        document.getElementById('redactionOption').classList.add('hidden');
    } else if (trackId === 'guardian') {
        fileInput.accept = ".txt,.json,.md,.csv,.log,.xml,.yaml,.yml,.pdf,.docx,.docm,.xlsx,.xlsm,.zip,.png,.jpg,.jpeg,.tiff,.bmp";
        document.getElementById('redactionOption').classList.remove('hidden');
    } else if (trackId === 'security') {
        fileInput.accept = ".txt,.json,.xml,.yaml,.yml,.py,.js,.ts,.go,.java,.cpp,.c,.h,.hpp,.rb,.php,.zip"; // expanded for source code
        document.getElementById('redactionOption').classList.add('hidden');
    } else {
        // Sentinel (Anything goes, usually Executables/Zips)
        fileInput.removeAttribute('accept');
        document.getElementById('redactionOption').classList.add('hidden');
    }

    currentTrack = trackId;

    // Update UI Text
    document.getElementById('trackTitle').textContent = tracks[trackId].title;
    document.getElementById('trackDesc').textContent = tracks[trackId].desc;
    document.getElementById('uploadRequirements').textContent = tracks[trackId].req;

    // Update Icon
    const iconPath = document.querySelector('#inputZone svg path');
    if (iconPath && tracks[trackId].icon) {
        iconPath.setAttribute('d', tracks[trackId].icon);
    }

    // Highlight Nav
    document.querySelectorAll('aside nav button').forEach(b => {
        const isTarget = b.id === `nav-${trackId}`;
        if (isTarget) {
            b.classList.add('bg-gray-800', 'text-white', 'border-l-4', 'border-brand');
            b.classList.remove('text-gray-400');
        } else {
            b.classList.remove('bg-gray-800', 'text-white', 'border-l-4', 'border-brand');
            b.classList.add('text-gray-400');
        }
    });

    // Reset View
    document.getElementById('resultsView').classList.add('hidden');
    document.getElementById('archiveView').classList.add('hidden');
    const usersView = document.getElementById('usersView');
    if (usersView) usersView.classList.add('hidden');
    const firewallView = document.getElementById('firewallView');
    if (firewallView) firewallView.classList.add('hidden');
    const metricsView = document.getElementById('metricsView');
    if (metricsView) metricsView.classList.add('hidden');

    document.getElementById('inputZone').classList.remove('hidden');

}

async function showArchive() {
    currentTrack = 'archive';

    // Update Nav
    document.querySelectorAll('aside nav button').forEach(b => {
        b.classList.remove('bg-gray-800', 'text-white', 'border-l-4', 'border-brand');
        b.classList.add('text-gray-400');
    });


    // Update Header
    document.getElementById('trackTitle').textContent = "SCAN REPORTS";
    document.getElementById('trackDesc').textContent = "Historical Scan Data & Reporting";

    // Toggle Views
    document.getElementById('inputZone').classList.add('hidden');
    document.getElementById('resultsView').classList.add('hidden');
    const usersView = document.getElementById('usersView');
    if (usersView) usersView.classList.add('hidden');
    const metricsView2 = document.getElementById('metricsView');
    if (metricsView2) metricsView2.classList.add('hidden');
    document.getElementById('archiveView').classList.remove('hidden');

    // Fetch Data
    const tbody = document.getElementById('archiveBody');
    tbody.innerHTML = '';
    document.getElementById('archiveLoading').classList.remove('hidden');
    document.getElementById('archiveEmpty').classList.add('hidden');

    try {
        const res = await fetch('/api/scans/');
        if (res.ok) {
            const scans = await res.json();
            document.getElementById('archiveLoading').classList.add('hidden');

            if (scans.length === 0) {
                document.getElementById('archiveEmpty').classList.remove('hidden');
                return;
            }

            // Add Header if not present
            const thead = document.querySelector('#archiveView table thead tr');
            if (thead && !thead.innerHTML.includes('TYPE')) {
                thead.innerHTML = `
                           <th class="text-left p-4 text-gray-400 font-normal">ID</th>
                           <th class="text-left p-4 text-gray-400 font-normal">DATE</th>
                           <th class="text-left p-4 text-gray-400 font-normal">TYPE</th>
                           <th class="text-left p-4 text-gray-400 font-normal">SOURCE</th>
                           <th class="text-left p-4 text-gray-400 font-normal">RISK</th>
                           <th class="text-left p-4 text-gray-400 font-normal">VERDICT</th>
                           <th class="text-left p-4 text-gray-400 font-normal">SCORE</th>
                       `;
            }

            scans.forEach(s => {
                const searchDate = new Date(s.created_at).toLocaleString();
                let riskClass = "text-gray-400";
                if (s.risk_level === 'CRITICAL') riskClass = "text-alert font-bold";
                if (s.risk_level === 'HIGH') riskClass = "text-alert";
                if (s.risk_level === 'MEDIUM') riskClass = "text-warning";
                if (s.risk_level === 'LOW') riskClass = "text-success";

                // Use Backend Scan Type
                let scanType = escapeHtml(s.scan_type || "DLP");
                let typeClass = "bg-blue-900/30 text-blue-400 border-blue-500/30";

                if (scanType === "VISION" || scanType === "OMNISENSE" || scanType === "ECHOVISION") {
                    typeClass = "bg-cyan-900/30 text-cyan-400 border-cyan-500/30";
                } else if (scanType === "MALWARE") {
                    typeClass = "bg-red-900/30 text-red-400 border-red-500/30";
                } else if (scanType === "CODE_SECURITY") {
                    typeClass = "bg-purple-900/30 text-purple-400 border-purple-500/30";
                }

                const rowId = `scan-${s.id}`;
                const detailId = `detail-${s.id}`;
                const safeSource = escapeHtml(s.source);
                const safeVerdict = escapeHtml(s.verdict || '--');
                const safeRisk = escapeHtml(s.risk_level || 'UNKNOWN');

                const row = document.createElement('tr');
                row.className = "hover:bg-white/5 transition cursor-pointer border-b border-white/5";
                row.onclick = () => {
                    const d = document.getElementById(detailId);
                    if (d) d.classList.toggle('hidden');
                };

                row.innerHTML = `
                           <td class="p-4 font-mono text-xs text-gray-500">COB-${s.id}</td>
                           <td class="p-4 text-xs">${searchDate}</td>
                           <td class="p-4 text-xs">
                               <span class="px-2 py-1 rounded border text-[10px] font-bold ${typeClass}">
                                   ${scanType}
                               </span>
                           </td>
                           <td class="p-4 text-xs font-mono max-w-[150px] truncate" title="${safeSource}">${safeSource.replace(/^(CODE_SECURITY|SUPPLY_CHAIN|OMNISENSE|ECHOVISION|VIDEO): ?/i, '')}</td>
                           <td class="p-4 text-xs ${riskClass}">${safeRisk}</td>
                           <td class="p-4 text-xs max-w-[200px] truncate" title="${safeVerdict}">${safeVerdict}</td>
                           <td class="p-4 font-mono font-bold">${s.threat_score}</td>
                        `;
                tbody.appendChild(row);

                // Detail Row
                const detailRow = document.createElement('tr');
                detailRow.id = detailId;
                detailRow.className = "hidden bg-gray-900/50";

                // Prepare AI Analysis Text
                let aiReason = "";
                if (s.ai_analysis) {
                    try {
                        let parsed = typeof s.ai_analysis === 'string' ? JSON.parse(s.ai_analysis) : s.ai_analysis;
                        if (parsed.reason) aiReason = parsed.reason;
                    } catch (e) { }
                }

                // Prepare Findings HTML
                let findingsHtml = '<span class="text-gray-500 italic">No findings detected.</span>';
                if (s.findings && s.findings.length > 0) {
                    findingsHtml = `<ul class="list-disc list-inside text-gray-400 space-y-1">`;
                    s.findings.forEach(f => {
                        const sev = f.severity ? escapeHtml(f.severity.toUpperCase()) : 'UNKNOWN';
                        let safeDetail = escapeHtml(f.detail || 'Match found');
                        let safeType = escapeHtml(f.type || 'Unknown');

                        if (safeDetail.startsWith('{')) {
                            try {
                                // If detail is just a score {"score": 0.85}, ignore it or show simplified
                                const parsed = JSON.parse(f.detail); // Parse ORIGINAL string
                                safeDetail = parsed.score ? `Confidence: ${Math.round(parsed.score * 100)}%` : 'Match found';
                            } catch (e) { }
                        }
                        findingsHtml += `<li><span class="text-xs font-bold ${sev === 'HIGH' || sev === 'CRITICAL' ? 'text-alert' : 'text-gray-500'}">[${sev}]</span> ${safeType}: <span class="font-mono text-xs">${safeDetail}</span></li>`;
                    });
                    findingsHtml += `</ul>`;
                }

                detailRow.innerHTML = `
                           <td colspan="7" class="p-6 border-b border-white/10 shadow-inner">
                               <div class="grid grid-cols-2 gap-6">
                                   <div>
                                       ${(s.source && s.source.startsWith('CODE_SECURITY')) || s.scan_type === 'CODE_SECURITY' ? '' : `
                                           <h4 class="text-xs font-bold text-gray-500 mb-2 uppercase tracking-wider">Analysis Summary</h4>
                                           <p class="text-sm text-gray-300 mb-4">${s.summary || s.verdict || 'No summary available.'}</p>
                                       `}
                                       
                                       ${aiReason && (!s.source || !s.source.startsWith('CODE_SECURITY')) ? `
                                        <div class="mt-4 p-3 bg-blue-900/10 border border-blue-500/20 rounded">
                                            <h5 class="text-[10px] font-bold text-blue-400 mb-1 uppercase">AI Analysis</h5>
                                            <p class="text-xs text-blue-200">${aiReason}</p>
                                        </div>` : ''}
                                   </div>
                                   <div>
                                       <h4 class="text-xs font-bold text-gray-500 mb-2 uppercase tracking-wider">Detailed Findings</h4>
                                       <div class="text-xs">
                                           ${findingsHtml}
                                       </div>
                                   </div>
                               </div>
                               
                               ${(() => {
                        let remediation = [];
                        let remediationHtml = '';
                        let contentHtml = '';
                        try {
                            // AI Remediation Plan (Flat Table)
                            remediation = [];
                            if (s.ai_analysis) {
                                try {
                                    const aiObj = (typeof s.ai_analysis === 'string') ? JSON.parse(s.ai_analysis) : s.ai_analysis;
                                    if (aiObj && aiObj.remediation) {
                                        remediation = aiObj.remediation;
                                    }
                                } catch (e) { }
                            }

                            remediationHtml = '';
                            if (remediation.length > 0) {
                                remediationHtml = `
                                            <div class="mt-6 border-t border-white/10 pt-4">
                                                <h4 class="text-xs font-bold text-gray-500 mb-2 uppercase tracking-wider">AI Remediation Plan</h4>
                                                <div class="max-h-[300px] overflow-y-auto border border-white/5 rounded bg-black/20 mt-2">
                                                    <table class="w-full text-xs text-left">
                                                        <thead class="bg-gray-800/50 sticky top-0">
                                                            <tr>
                                                                <th class="py-2 px-3 text-gray-400 font-normal">Package</th>
                                                                <th class="py-2 px-3 text-gray-400 font-normal">CVE / Issue</th>
                                                                <th class="py-2 px-3 text-gray-400 font-normal">Current</th>
                                                                <th class="py-2 px-3 text-gray-400 font-normal">Recommended Action</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody class="divide-y divide-white/5">
                                                            ${remediation.map(item => `
                                                                <tr class="hover:bg-white/5 transition-colors">
                                                                    <td class="py-2 px-3 text-sm text-white font-medium align-top">${item.package || 'Unknown'}</td>
                                                                    <td class="py-2 px-3 text-sm text-rose-400 font-mono align-top">${item.cve || item.vulnerability || 'N/A'}</td>
                                                                    <td class="py-2 px-3 text-sm text-gray-400 align-top">${item.current_version || '?'}</td>
                                                                    <td class="py-2 px-3 text-sm text-emerald-400 align-top">
                                                                        <div class="font-bold flex items-center gap-1">
                                                                            ${item.fixed_version || 'Update'}
                                                                            ${item.action ? '' : '<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>'}
                                                                        </div>
                                                                        ${item.action ? `<div class="text-[10px] mt-1 opacity-80">${item.action}</div>` : ''}
                                                                    </td>
                                                                </tr>
                                                            `).join('')}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>
                                        `;
                            }

                            contentHtml = '';
                            if (s.content && (s.content.startsWith('{') || s.content.startsWith('['))) {
                                const data = JSON.parse(s.content);
                                if (data.segments) {
                                    contentHtml = `
                                               <div class="mt-6 border-t border-white/10 pt-4">
                                                   <h4 class="text-xs font-bold text-gray-500 mb-2 uppercase tracking-wider flex justify-between">
                                                       <span>Timestamped Transcript</span>
                                                       <span class="text-[10px] text-cyan-400">Media source stored locally</span>
                                                   </h4>
                                                   <div class="max-h-[300px] overflow-y-auto border border-white/5 rounded bg-black/20 mt-2">
                                                       <table class="w-full text-xs text-left">
                                                           <tbody class="divide-y divide-white/5">
                                                               ${data.segments.map(seg => `
                                                                   <tr class="hover:bg-white/5 transition-colors group">
                                                                       <td class="p-2 font-mono text-[10px] text-cyan-400 whitespace-nowrap align-top w-20 opacity-70 group-hover:opacity-100">
                                                                           ${new Date(seg.start * 1000).toISOString().substr(14, 5)}
                                                                       </td>
                                                                       <td class="p-2 text-gray-300 align-top leading-relaxed">${seg.text}</td>
                                                                   </tr>
                                                               `).join('')}
                                                           </tbody>
                                                       </table>
                                                   </div>
                                               </div>`;
                                } else if (data.text) {
                                    // Check if this is a structured Text Report from Code Security
                                    if (data.text.includes('📦') || data.text.includes('VULNERABILITIES')) {
                                        const lines = data.text.split('\n');
                                        let rows = '';
                                        let currentPkg = '';

                                        lines.forEach(line => {
                                            line = line.trim();
                                            if (!line) return;

                                            if (line.startsWith('📦')) {
                                                currentPkg = line.substring(1).trim(); // Remove '📦'
                                            } else if (line.startsWith('- [')) {
                                                // - [CVE] Desc
                                                // format: - [CVE-XXX] Description
                                                const parts = line.split(']');
                                                const cve = parts[0].replace('- [', '').trim();
                                                const desc = parts.slice(1).join(']').trim();

                                                rows += `
                                                            <tr class="hover:bg-white/5 transition-colors text-xs border-b border-white/5">
                                                                <td class="p-2 text-white font-medium align-top whitespace-nowrap">${currentPkg}</td>
                                                                <td class="p-2 text-rose-400 font-mono align-top whitespace-nowrap">${cve}</td>
                                                                <td class="p-2 text-gray-300 align-top">${desc}</td>
                                                            </tr>
                                                         `;
                                            } else if (line.startsWith('Fixed in:')) {
                                                // Append to previous row if possible, but for simplicity let's just make it its own mini-row or handled in parsing
                                                // Actually, simpler to just append nicely.
                                                // Let's attach it to the description of the *last* row added? 
                                                // Complex with string concatenation.
                                                // Alternative: Let's just treat it as a finding detail.
                                                rows += `
                                                            <tr class="bg-black/20 text-[10px] border-b border-white/5">
                                                                <td class="p-1 text-right text-emerald-500 font-bold" colspan="3">➤ ${line}</td>
                                                            </tr>
                                                         `;
                                            }
                                        });

                                        return `
                                                <div class="mt-6 border-t border-white/10 pt-4">
                                                     <h4 class="text-xs font-bold text-gray-500 mb-2 uppercase tracking-wider flex justify-between">
                                                         <span>Vulnerability Report</span>
                                                         <span class="text-[10px] text-cyan-400">Parsed from Scan</span>
                                                     </h4>
                                                     <div class="max-h-[300px] overflow-y-auto border border-white/5 rounded bg-black/20 mt-2">
                                                         <table class="w-full text-left">
                                                             <thead class="bg-gray-800/50 sticky top-0">
                                                                 <tr class="text-[10px] text-gray-400 font-normal">
                                                                     <th class="p-2">Package</th>
                                                                     <th class="p-2">CVE/ID</th>
                                                                     <th class="p-2">Description</th>
                                                                 </tr>
                                                             </thead>
                                                             <tbody class="divide-y divide-white/5">
                                                                 ${rows}
                                                             </tbody>
                                                         </table>
                                                     </div>
                                                </div>`;
                                    }

                                    return `
                                                <div class="mt-6 border-t border-white/10 pt-4">
                                                     <h4 class="text-xs font-bold text-gray-500 mb-2 uppercase tracking-wider">Transcript / Report</h4>
                                                     <pre class="whitespace-pre-wrap font-mono text-xs text-gray-400 bg-black/20 p-2 rounded">${data.text}</pre>
                                                </div>`;
                                }
                            }
                        } catch (e) { }
                        return contentHtml + remediationHtml;
                    })()}
                        </td>
                    `;
                tbody.appendChild(detailRow);
            });

        } else {
            throw new Error('Failed to fetch scans');
        }
    } catch (e) {
        console.error(e);
        document.getElementById('archiveLoading').textContent = "ERROR_FETCHING_DATA";
    }
}

// --- Staging Logic ---
let stagedFile = null;
let stagedEndpoint = null;

function handleFileSelection(input) {
    let endpoint = `/api/scans/upload_file?track=${currentTrack}`;
    if (currentTrack === 'security') {
        endpoint = '/api/security/scan';
    }
    stageUpload(input, endpoint);
}

function handleVideoSelection(input) {
    stageUpload(input, '/api/scans/upload_video');
}

function stageUpload(input, endpoint) {
    const file = input.files[0];
    if (!file) return;

    stagedFile = file;
    stagedEndpoint = endpoint;

    // Show Staging View
    document.getElementById('inputZone').classList.add('hidden');
    document.getElementById('stagingView').classList.remove('hidden');

    // Metadata
    document.getElementById('stagedFileName').textContent = file.name;
    document.getElementById('stagedFileSize').textContent = formatBytes(file.size);

    // Redaction Check (Only for Guardian and text/doc types)
    const ext = file.name.split('.').pop().toLowerCase();
    const supportedRedaction = ['txt', 'json', 'md', 'csv', 'log', 'xml', 'yaml', 'yml', 'pdf', 'docx', 'docm', 'xlsx', 'xlsm'];

    const redOpt = document.getElementById('redactionOption');
    // DISABLED BY USER REQUEST: Always hide redaction option
    redOpt.classList.add('hidden');
    /*
    if (currentTrack === 'guardian' && supportedRedaction.includes(ext)) {
        redOpt.classList.remove('hidden');
        document.getElementById('correctCheckbox').checked = false; // Reset
    } else {
        redOpt.classList.add('hidden');
    }
    */
}

function cancelStaging() {
    stagedFile = null;
    stagedEndpoint = null;
    document.getElementById('stagingView').classList.add('hidden');
    document.getElementById('inputZone').classList.remove('hidden');
    document.getElementById('fileInput').value = '';
    document.getElementById('videoInput').value = '';
}

async function startScan() {
    if (!stagedFile || !stagedEndpoint) return;
    await processUpload(stagedFile, stagedEndpoint);
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// --- Upload Logic ---
async function processUpload(file, endpoint) {
    if (!file) return;

    // Update UI
    document.getElementById('nav-vision').classList.remove('active-tab');
    document.getElementById('nav-security').classList.remove('active-tab');
    document.getElementById('nav-firewall').classList.remove('active-tab');
    document.getElementById('nav-users').classList.remove('active-tab');

    // Hide previous results
    document.getElementById('resultsView').classList.add('hidden');
    document.getElementById('btnDownloadSafe').classList.add('hidden');

    const formData = new FormData();
    formData.append('file', file);

    const headers = {};
    // Cookie handles auth automatically

    // Handle URL params
    let url = new URL(endpoint, window.location.origin);

    // Append correct=true if checked AND visible
    const redOpt = document.getElementById('redactionOption');
    if (!redOpt.classList.contains('hidden') && document.getElementById('correctCheckbox').checked) {
        url.searchParams.append('correct', 'true');
    }

    try {
        // Ensure track param is present if needed (endpoint usually has it constructed)
        const res = await fetch(url.toString(), {
            method: 'POST',
            headers: headers,
            body: formData
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Upload Failed');

        renderResults(data);

        // Refresh User Data (Credits)
        await setupAuth();

    } catch (e) {
        alert(`SCAN_FAILED: ${e.message} `);
        window.location.reload(); // Simple reset
    } finally {
        document.getElementById('loader').classList.add('hidden');
        // Reset Staging
        stagedFile = null;
        document.getElementById('fileInput').value = '';
        document.getElementById('videoInput').value = '';
    }
}

// Removed old handlers that directly processed input
/*
async function handleFileUpload(input) { ... }
async function handleVideoUpload(input) { ... }
*/

async function performSafeWash() {
    const btn = document.getElementById('btnSafeWash');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `< svg class="w-4 h-4 animate-spin" fill = "none" viewBox = "0 0 24 24" stroke = "currentColor" > <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg > SCRUBBING...`;

    // Simulate CDR Logic
    await new Promise(r => setTimeout(r, 2000));

    btn.innerHTML = `< svg class="w-4 h-4" fill = "none" stroke = "currentColor" viewBox = "0 0 24 24" > <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg > WASH COMPLETE`;
    btn.classList.remove('bg-green-600');
    btn.classList.add('bg-blue-600');

    // Add a "Sanitized" badge to findings
    const findingsDiv = document.getElementById('scanFindings');
    const washBanner = document.createElement('div');
    washBanner.className = "col-span-full bg-blue-500/10 border border-blue-500/20 p-4 rounded-xl text-blue-400 text-sm flex items-center gap-3 animate-bounce";
    washBanner.innerHTML = `< svg class="w-6 h-6" fill = "none" stroke = "currentColor" viewBox = "0 0 24 24" > <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg >
                    <span><strong>SAFE WASH SUCCESSFUL:</strong> All active threats, PII, and suspicious macros have been disarmed. A clean copy of this file has been archived.</span>`;
    findingsDiv.prepend(washBanner);
}



function renderResults(data) {
    currentScanResult = data;

    const resultsDiv = document.getElementById('resultsView');
    resultsDiv.classList.remove('hidden');

    resultsDiv.classList.remove('hidden');

    // --- VIEW TOGGLING ---
    // Enhanced Code Security Check
    const isCodeSec = currentTrack === 'security' ||
        (data.source && data.source.startsWith('CODE_SECURITY')) ||
        (data.scan_type === 'CODE_SECURITY' || data.scan_type === 'Static Code Analysis') ||
        (data.verdict && data.verdict.includes("Scan complete."));

    const standardView = document.getElementById('standardResultsContent');
    const codeSecurityView = document.getElementById('codeSecurityView');

    if (isCodeSec && codeSecurityView) {
        if (standardView) standardView.classList.add('hidden');
        codeSecurityView.classList.remove('hidden');

        // Prepare AI Result
        let aiResult = {};
        try {
            if (data.ai_analysis) {
                aiResult = typeof data.ai_analysis === 'string' ? JSON.parse(data.ai_analysis) : data.ai_analysis;
            }
        } catch (e) { }

        renderCodeSecurityView(data, aiResult);

        // Update Credits
        if (data.credits_remaining !== undefined) {
            updateCredits(data.credits_remaining);
        }
        return; // Stop standard rendering
    } else {
        // Standard View
        if (standardView) standardView.classList.remove('hidden');
        if (codeSecurityView) codeSecurityView.classList.add('hidden');
    }

    // Standard View (Fallback or active)
    if (standardView) standardView.classList.remove('hidden');

    // --- STANDARD RENDERING ---


    // Score
    const score = data.threat_score || 0;
    const scoreEl = document.getElementById('scoreValue');
    scoreEl.innerHTML = `${score} <span class="text-xl text-gray-600">/100</span>`;
    if (score > 80) scoreEl.className = "text-5xl font-black text-alert";
    else if (score > 50) scoreEl.className = "text-5xl font-black text-warning";
    else scoreEl.className = "text-5xl font-black text-success";

    // Verdict
    const vBox = document.getElementById('verdictBox');
    let vText = data.verdict || 'UNKNOWN';

    // 1. Strip internal prefix if present (Backend sometimes leaks VERDICT_REVIEW)
    vText = vText.replace(/^VERDICT_/, '');

    // 2. Simple truncation if too long (e.g. legacy scans)
    if (vText.length > 30 && vText.includes(':')) {
        vText = vText.split(':')[0]; // Take only the prefix status
    }

    vBox.textContent = vText;

    if (data.risk_level === 'CRITICAL' || data.risk_level === 'HIGH') {
        vBox.className = "mt-4 p-2 rounded text-[11px] font-mono border bg-red-900/20 border-alert/30 text-alert";
    } else if (data.risk_level === 'LOW') {
        vBox.className = "mt-4 p-2 rounded text-[11px] font-mono border bg-green-900/20 border-success/30 text-success";
    } else {
        vBox.className = "mt-4 p-2 rounded text-[11px] font-mono border bg-orange-900/20 border-warning/30 text-warning";
    }

    // Context
    document.getElementById('scanDuration').textContent = data.scan_duration_ms || 0;
    document.getElementById('resScanId').textContent = data.id || '--';

    // 1. Basic Summary
    // Sanitize: If summary looks like JSON, use verdict instead.
    let summaryText = data.summary || "Scan completed successfully.";
    if (summaryText.trim().startsWith('{')) {
        summaryText = data.verdict || "Scan complete.";
    }
    document.getElementById('scanSummary').innerText = summaryText;

    // 2. AI Analysis & Remediation
    const aiInsightPanel = document.getElementById('aiInsightPanel');
    const aiSummaryText = document.getElementById('aiSummaryText');
    const remediationPanel = document.getElementById('remediationPanel');
    const remediationTable = document.getElementById('remediationTableBody');
    const findingsPanel = document.getElementById('findingsPanelContainer');

    // Reset
    if (aiInsightPanel) aiInsightPanel.classList.add('hidden');
    if (remediationPanel) remediationPanel.classList.add('hidden');
    if (remediationTable) remediationTable.innerHTML = '';

    // Check Scan Type logic (using source, scan_type, AND verdict heuristic)
    // Check Scan Type logic (using source, scan_type, AND verdict heuristic)
    // Reuse isCodeSec from top of function

    if (isCodeSec) {
        // FORCE CLEAR SUMMARY
        if (document.getElementById('scanSummary')) document.getElementById('scanSummary').innerText = data.verdict;
        if (aiSummaryText) aiSummaryText.innerText = "";

        // Keep the JSON dump hidden
        if (findingsPanel) findingsPanel.classList.add('hidden');
    } else {
        if (findingsPanel) findingsPanel.classList.remove('hidden');
    }

    let aiResult = null;
    if (data.ai_analysis) {
        try {
            // Initial Parse
            let parsed = typeof data.ai_analysis === 'string' ? JSON.parse(data.ai_analysis) : data.ai_analysis;

            // AGGRESSIVE UNWRAP SEARCH
            // We look for an object that has 'remediation' or 'summary'
            let candidates = [parsed];

            if (parsed.ai_analysis) {
                candidates.push(parsed.ai_analysis);
                // Handle simplified double-string-encoding case
                if (typeof parsed.ai_analysis === 'string') {
                    try { candidates.push(JSON.parse(parsed.ai_analysis)); } catch (e) { }
                }
            }

            // Priority 1: Has Remediation Array (This is what builds the table)
            const hasRemediation = (obj) => obj && Array.isArray(obj.remediation) && obj.remediation.length > 0;

            // Priority 2: Has Summary (Fallback)
            const hasSummary = (obj) => obj && obj.summary;

            // Select best candidate
            aiResult = candidates.find(hasRemediation) || candidates.find(hasSummary) || parsed;

        } catch (e) {
            console.error("Failed to parse AI analysis", e);
        }
    }

    if (aiResult) {
        // Populate AI Insight Block
        // Logic: 
        // - If Code Security: Show Clean Summary (result.summary), Hide Raw JSON.
        // - If Other: Show standard reason/verdict.

        if (isCodeSec) {
            // Show Clean Summary only
            if (aiResult.summary) {
                aiInsightPanel.classList.remove('hidden');
                aiSummaryText.innerText = aiResult.summary;
            } else if (aiResult.verdict) {
                aiInsightPanel.classList.remove('hidden');
                aiSummaryText.innerText = aiResult.verdict;
            } else {
                aiInsightPanel.classList.add('hidden');
            }
        } else {
            // Standard Logic
            if (aiResult.reason || aiResult.verdict) {
                aiInsightPanel.classList.remove('hidden');

                // Enhanced UI for ML Metadata
                if (aiResult.ml_model && aiResult.confidence !== undefined) {
                    const conf = aiResult.confidence * 100;
                    const label = aiResult.inference_label || aiResult.verdict;

                    let colorClass = "text-gray-400 border-gray-600";
                    let barColor = "bg-gray-500";

                    if (label.includes("sensitive") || label.includes("BLOCK") || label === "sensitive confidential data") {
                        colorClass = "text-alert border-alert bg-alert/10";
                        barColor = "bg-alert";
                    } else if (label.includes("safe") || label.includes("ALLOW")) {
                        colorClass = "text-success border-success bg-success/10";
                        barColor = "bg-success";
                    }

                    aiSummaryText.innerHTML = `
                        <div class="grid grid-cols-1 gap-4">
                            <!-- 1. Model Header -->
                            <div class="flex items-center justify-between border-b border-gray-700/50 pb-2">
                                <span class="text-[10px] font-bold uppercase tracking-wider text-gray-500">Analysis Engine</span>
                                <span class="text-[10px] font-mono text-brand bg-brand/10 px-2 py-0.5 rounded border border-brand/20">${escapeHtml(aiResult.ml_model)}</span>
                            </div>
                            
                            <!-- 2. Combined Findings Summary (Threat Analysis) -->
                            <div class="bg-gray-800/50 rounded p-3 border border-gray-700">
                                <div class="text-[10px] uppercase text-gray-500 font-bold mb-2">Threat Analysis</div>
                                <div class="text-xs text-gray-300 space-y-1">
                                    ${(data.findings && data.findings.length > 0) ?
                            data.findings.slice(0, 3).map(f => `
                                            <div class="flex justify-between">
                                                <span>• ${escapeHtml(f.type)}</span>
                                                <span class="${f.severity === 'CRITICAL' ? 'text-red-500' : 'text-yellow-500'} font-mono text-[10px]">${f.severity}</span>
                                            </div>
                                        `).join('')
                            : '<span class="text-gray-500 italic">No specific patterns matched.</span>'}
                                     ${(data.findings && data.findings.length > 3) ? `<div class="text-[10px] text-gray-500 pl-2">+ ${data.findings.length - 3} more</div>` : ''}
                                </div>
                            </div>

                            <!-- 3. AI Verdict & Confidence -->
                            <div class="bg-gray-800/50 rounded p-3 border border-gray-700">
                                <div class="text-[10px] uppercase text-gray-500 font-bold mb-2">AI Assessment</div>
                                <div class="flex justify-between items-center mb-2">
                                    <span class="text-xs text-gray-300">Classification</span>
                                    <span class="px-2 py-0.5 rounded text-xs font-bold border ${colorClass} uppercase tracking-wide">${escapeHtml(label)}</span>
                                </div>
                                <div class="w-full h-1.5 bg-gray-900 rounded-full overflow-hidden mb-1">
                                    <div class="h-full ${barColor}" style="width: ${conf}%"></div>
                                </div>
                                <div class="text-right text-[10px] text-gray-500 font-mono">Confidence: ${conf.toFixed(1)}%</div>
                            </div>

                            <!-- 4. Final Recommendation -->
                            <div class="mt-1 pt-3 border-t border-gray-700/50">
                                <div class="flex items-center justify-between">
                                    <span class="text-xs font-bold text-gray-400 uppercase">Recommendation</span>
                                    <span class="text-sm font-bold ${label.includes('sensitive') ? 'text-red-400' : 'text-green-400'}">
                                        ${label.includes('sensitive') ? '🚫 BLOCK TRANSFER' : '✅ ALLOW TRANSFER'}
                                    </span>
                                </div>
                            </div>
                        </div>
                    `;

                } else {
                    // Fallback to text
                    aiSummaryText.innerText = aiResult.reason || `Verdict: ${aiResult.verdict}`;
                }
            }
        }

        // Populate Remediation Plan (Handles nested structure)
        let remediationList = aiResult.remediation || (aiResult.ai_analysis && aiResult.ai_analysis.remediation) || [];


        if (remediationList && Array.isArray(remediationList) && remediationList.length > 0) {
            remediationPanel.classList.remove('hidden');
            remediationList.forEach(item => {
                const tr = document.createElement('tr');
                tr.className = "border-b border-gray-800 hover:bg-white/5";

                // Parse Package/CVE
                let pkg = item.package || "Unknown";
                let cve = item.cve || "";

                // Severity Color
                // Try to find severity from findings if possible, or just use generic
                // Severity Color Map
                let sevClass = "text-gray-400";
                const s = (item.severity || "").toUpperCase();
                if (s === "CRITICAL") sevClass = "text-red-500 font-bold";
                else if (s === "HIGH") sevClass = "text-orange-500 font-bold";
                else if (s === "MEDIUM") sevClass = "text-yellow-500";
                else if (s === "LOW") sevClass = "text-blue-400";

                // Action Link Logic
                let actionHtml = `<span class="italic text-gray-500">${item.action || 'Upgrade'}</span>`;
                if (item.link) {
                    actionHtml = `<a href="${item.link}" target="_blank" class="text-brand hover:text-white underline decoration-dotted underline-offset-4 flex items-center gap-1">
                                ${item.action || 'View Fix'}
                                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                            </a>`;
                }

                tr.innerHTML = `
                            <td class="p-4 align-top">
                                <div class="font-bold text-gray-200">${escapeHtml(pkg)}</div>
                                <div class="text-xs text-gray-500 font-mono mt-1">Current: <span class="text-gray-400">${escapeHtml(item.current_version || 'Unknown')}</span></div>
                            </td>
                            <td class="p-4 align-top">
                                <div class="text-xs text-brand font-mono leading-relaxed max-w-xs break-words">${escapeHtml(cve)}</div>
                            </td>
                            <td class="p-4 align-top whitespace-nowrap">
                                <span class="${sevClass} text-xs uppercase tracking-wide px-2 py-1 rounded bg-gray-800/50 border border-gray-700">${escapeHtml(item.severity || 'Unknown')}</span>
                            </td>
                            <td class="p-4 align-top whitespace-nowrap">
                                <div class="font-bold text-success text-sm">${escapeHtml(item.fixed_version || 'Check Report')}</div>
                            </td>
                            <td class="p-4 align-top text-xs">
                                ${actionHtml}
                            </td>
                        `;
                remediationTable.appendChild(tr);
            });
        }
    }

    // Display Report if available (Fallback/Append)
    if (data.report && summaryText.length < 50) {
        // If summary is short/empty, maybe show a bit of report
        // But better to leave it clean.
    }

    // Handle CDR / Redaction URL
    const btnDownload = document.getElementById('btnDownloadSafe');
    btnDownload.classList.add('hidden');

    // Check for Safe Wash (CDR) or Redaction
    let downloadUrl = null;
    let downloadLabel = "DOWNLOAD SAFE COPY";

    if (aiResult) {
        if (aiResult.cdr && aiResult.cdr.url) {
            downloadUrl = aiResult.cdr.url;
            downloadLabel = "DOWNLOAD SAFE COPY (CDR)";
        }
        if (aiResult.redaction && aiResult.redaction.url) {
            downloadUrl = aiResult.redaction.url;
            downloadLabel = "DOWNLOAD REDACTED COPY";
        }
    }

    if (downloadUrl) {
        btnDownload.href = downloadUrl;
        btnDownload.innerHTML = `
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4">
                        </path>
                    </svg>
                    ${downloadLabel}`;
        btnDownload.classList.remove('hidden');
    }

    // Summary Update
    document.getElementById('scanSummary').innerText = summaryText;

    // Compliance Alerts
    const complianceDiv = document.getElementById('complianceAlerts');
    let alerts = [];

    // AI Result Object (Reuse existing aiResult from above)

    if (aiResult) {
        // 1. From explicit alerts field
        if (aiResult.compliance_alerts && Array.isArray(aiResult.compliance_alerts)) {
            alerts = aiResult.compliance_alerts;
        }

        // 2. From Tags in Reason (Legacy/LangChain)
        if (aiResult.reason) {
            const tagRegex = /\[(HIPAA|PCI|SOC2|GDPR|ISO27001)[^\]]*\]/gi;
            const matches = aiResult.reason.match(tagRegex);
            if (matches) {
                matches.forEach(m => {
                    const tag = m.replace(/[\[\]]/g, '').toUpperCase();
                    if (!alerts.includes(tag)) alerts.push(tag);
                });
            }
        }
    }

    if (complianceDiv) {
        complianceDiv.innerHTML = '';
        if (alerts.length > 0) {
            complianceDiv.classList.remove('hidden');
            alerts.forEach(alert => {
                const span = document.createElement('span');
                span.className = 'px-2 py-1 bg-red-900/50 text-red-200 text-xs rounded border border-red-700 font-mono mr-2 mb-2 inline-block';
                span.innerText = alert; // innerText is safe
                complianceDiv.appendChild(span);
            });
        } else {
            complianceDiv.classList.add('hidden');
        }
    }

    // --- NEW: Code Security View Switcher ---



    // Visualize Flow
    const findings = data.findings || [];

    // Flow Containers
    const flowMalware = document.getElementById('flow-malware');
    const flowDLP = document.getElementById('flow-dlp');
    const flowCodeSec = document.getElementById('flow-code-sec');

    // Determine Flow Type
    const scanType = (data.scan_type || 'SENTINEL').toUpperCase();

    // Code Security Flow
    if (isCodeSecurity || scanType === 'STATIC CODE ANALYSIS') {
        if (flowMalware) flowMalware.classList.add('hidden');
        if (flowDLP) flowDLP.classList.add('hidden');
        if (flowCodeSec) flowCodeSec.classList.remove('hidden');

        // Animate Steps (Trivy -> OSV -> Remediation)
        setTimeout(() => {
            document.getElementById('step-trivy').classList.replace('text-gray-400', 'text-brand');
            document.getElementById('step-trivy').classList.replace('border-gray-600', 'border-brand');
        }, 500);

        setTimeout(() => {
            document.getElementById('step-osv').classList.replace('text-gray-400', 'text-brand');
            document.getElementById('step-osv').classList.replace('border-gray-600', 'border-brand');
        }, 1200);

        setTimeout(() => {
            document.getElementById('step-remediate').classList.replace('text-gray-400', 'text-brand');
            document.getElementById('step-remediate').classList.replace('border-gray-600', 'border-brand');
        }, 1800);

    }
    // DLP Flow
    else if (['GUARDIAN', 'DLP', 'VISION', 'OMNISENSE', 'ECHOVISION'].includes(scanType)) {
        if (flowMalware) flowMalware.classList.add('hidden');
        if (flowCodeSec) flowCodeSec.classList.add('hidden');
        if (flowDLP) flowDLP.classList.remove('hidden');


        const steps = {
            regex: document.getElementById('step-regex'),
            ai: document.getElementById('step-ai'),
            context: document.getElementById('step-context'),
            redact: document.getElementById('step-redact')
        };

        // Reset DLP Steps
        if (steps.regex && steps.ai && steps.context) {
            Object.values(steps).forEach(el => {
                if (!el) return;
                el.classList.remove('text-brand', 'text-alert', 'text-success', 'border-brand', 'border-alert', 'border-success', 'border-gray-600', 'text-gray-400');
                el.classList.add('border-gray-600', 'text-gray-400');
            });

            // 1. Regex Engine (Always runs)
            steps.regex.classList.remove('border-gray-600', 'text-gray-400');
            steps.regex.classList.add('border-brand', 'text-brand');

            // 2. AI Analysis
            if (data.ai_analysis) {
                steps.ai.classList.remove('border-gray-600', 'text-gray-400');
                steps.ai.classList.add('border-brand', 'text-brand');
            }

            // 3. Context Scan (Final Analysis)
            // If we have AI analysis, we did context scan
            if (data.ai_analysis) {
                steps.context.classList.remove('border-gray-600', 'text-gray-400');
                steps.context.classList.add('border-brand', 'text-brand');
            }

            // 4. Safe Wash (Conditional)
            const line = document.getElementById('line-cdr-dlp');
            const container = document.getElementById('container-cdr-dlp');
            let hasRedaction = false;

            if (data.ai_analysis) {
                try {
                    const ai = typeof data.ai_analysis === 'string' ? JSON.parse(data.ai_analysis) : data.ai_analysis;
                    if (ai.redaction) hasRedaction = true;
                } catch (e) { }
            }

            if (hasRedaction) {
                if (line) line.classList.remove('hidden');
                if (container) container.classList.remove('hidden');
                if (steps.redact) {
                    steps.redact.classList.remove('border-gray-600', 'text-gray-400');
                    steps.redact.classList.add('border-success', 'text-success');
                }
            } else {
                // Hide if not present
                if (line) line.classList.add('hidden');
                if (container) container.classList.add('hidden');
            }
        }

    } else {
        // Show Malware Flow (Default)
        if (flowDLP) flowDLP.classList.add('hidden');
        if (flowCodeSec) flowCodeSec.classList.add('hidden');
        if (flowMalware) flowMalware.classList.remove('hidden');

        const isMalware = findings.some(f => f.type.toLowerCase().includes('malware') || f.type.toLowerCase().includes('clamav') || f.type.toLowerCase().includes('yara'));
        const steps = {
            av: document.getElementById('step-av'),
            yara: document.getElementById('step-yara'),
            macro: document.getElementById('step-macro'),
            cdr: document.getElementById('step-cdr-malware')
        };

        // Reset Malware Steps
        if (steps.av && steps.yara && steps.macro) {
            Object.values(steps).forEach(el => {
                if (!el) return;
                el.classList.remove('text-brand', 'text-alert', 'text-success', 'border-brand', 'border-alert', 'border-success', 'border-gray-600', 'text-gray-400');
                el.classList.add('border-gray-600', 'text-gray-400');
            });

            // AV & YARA Status
            if (isMalware) {
                if (steps.av) { steps.av.classList.remove('border-gray-600', 'text-gray-400'); steps.av.classList.add('border-alert', 'text-alert'); }
                if (steps.yara) { steps.yara.classList.remove('border-gray-600', 'text-gray-400'); steps.yara.classList.add('border-alert', 'text-alert'); }
                if (steps.macro) { steps.macro.classList.remove('border-gray-600', 'text-gray-400'); steps.macro.classList.add('border-alert', 'text-alert'); }

            } else {
                if (steps.av) { steps.av.classList.remove('border-gray-600', 'text-gray-400'); steps.av.classList.add('border-brand', 'text-brand'); }
                if (steps.yara) { steps.yara.classList.remove('border-gray-600', 'text-gray-400'); steps.yara.classList.add('border-brand', 'text-brand'); }
                if (steps.macro) { steps.macro.classList.remove('border-gray-600', 'text-gray-400'); steps.macro.classList.add('border-brand', 'text-brand'); }
            }

            // Safe Wash (CDR) - Conditional
            const cdrInfo = data.cdr_info;
            const line = document.getElementById('line-cdr-malware');
            const container = document.getElementById('container-cdr-malware');

            if (cdrInfo) {
                if (line) line.classList.remove('hidden');
                if (container) container.classList.remove('hidden');

                if (cdrInfo.status === 'success' || cdrInfo.status === 'local_only') {
                    if (steps.cdr) {
                        steps.cdr.classList.remove('border-gray-600', 'text-gray-400');
                        steps.cdr.classList.add('border-success', 'text-success'); // Green for Clean
                    }
                } else {
                    if (steps.cdr) {
                        steps.cdr.classList.remove('border-gray-600', 'text-gray-400');
                        steps.cdr.classList.add('border-warning', 'text-warning'); // Warning if failed
                    }
                }
            } else {
                // Hide if not run
                if (line) line.classList.add('hidden');
                if (container) container.classList.add('hidden');
            }
        }
    }

    // Findings Table
    const tbody = document.getElementById('findingsBody');
    tbody.innerHTML = '';

    if (data.findings && data.findings.length > 0) {
        document.getElementById('noFindings').classList.add('hidden');

        // 0. Compliance Impact Row (Top Priority)
        let impacts = [];
        if (aiResult && aiResult.compliance_alerts && Array.isArray(aiResult.compliance_alerts)) {
            impacts = aiResult.compliance_alerts;
        }

        if (impacts.length > 0) {
            const row = document.createElement('tr');
            row.classList.add('bg-red-900/10', 'border-l-4', 'border-alert');
            row.innerHTML = `
                        <td class="p-4 font-bold text-alert font-mono">COMPLIANCE IMPACT</td>
                        <td class="p-4 text-alert font-bold uppercase">CRITICAL</td>
                        <td class="p-4 font-mono text-gray-300">
                            Potential violation of: ${impacts.map(i => `<span class="px-2 py-0.5 bg-red-500/20 text-red-200 rounded border border-red-500/50 mx-1">${i}</span>`).join('')}
                        </td>
                `;
            tbody.appendChild(row);
        }

        // Aggregate Findings
        const aggregated = {};
        data.findings.forEach(f => {
            const metaStr = typeof f.metadata === 'object' ? JSON.stringify(f.metadata) : (f.detail || '');
            const key = `${f.type}| ${f.severity}| ${metaStr} `;

            if (!aggregated[key]) {
                aggregated[key] = {
                    type: f.type,
                    severity: f.severity,
                    meta: metaStr,
                    count: 0
                };
            }


            aggregated[key].count += 1;
        });

        // Render Aggregated Findings
        Object.values(aggregated).forEach(item => {
            const row = document.createElement('tr');

            let sevClass = "text-gray-400";
            if (item.severity === 'high' || item.severity === 'HIGH') sevClass = "text-alert font-bold";
            if (item.severity === 'medium' || item.severity === 'MEDIUM') sevClass = "text-warning";
            if (item.severity === 'critical' || item.severity === 'CRITICAL') sevClass = "text-red-500 font-black";

            const countBadge = item.count > 1 ? `<span class="ml-2 px-2 py-0.5 bg-gray-700 rounded text-xs text-white">x${item.count}</span>` : '';

            row.innerHTML = `
                <td class="p-4 font-bold text-gray-300 font-mono flex items-center">
                    ${escapeHtml(item.type)} ${countBadge}
                </td>
                <td class="p-4 ${sevClass} uppercase">${escapeHtml(item.severity)}</td>
                <td class="p-4 font-mono text-gray-500 break-all text-xs">${escapeHtml(item.meta)}</td>
            `;
            tbody.appendChild(row);
        });
    } else {
        document.getElementById('noFindings').classList.remove('hidden');
    }

    // Append Report Text if available (Security Track)
    if (data.report) {
        const row = document.createElement('tr');
        row.innerHTML = `
                    <td class="p-4 font-bold text-gray-300 font-mono" colspan="3">
                        <div class="font-bold text-brand mb-2">FULL SCAN REPORT</div>
                        <pre class="whitespace-pre-wrap font-mono text-xs text-gray-400 bg-black/20 p-4 rounded overflow-auto max-h-[300px]">${data.report}</pre>
                    </td>
                     `;
        if (document.getElementById('noFindings').classList.contains('hidden')) {
            tbody.appendChild(row);
        } else {
            document.getElementById('noFindings').classList.add('hidden');
            tbody.appendChild(row);
        }
    }

    // Update Credits if returned
    if (data.credits_remaining !== undefined) {
        updateCredits(data.credits_remaining);
    }
}

function copyJSON() {
    if (!currentScanResult) return;
    navigator.clipboard.writeText(JSON.stringify(currentScanResult, null, 2));
    alert('JSON copied to clipboard');
}

function renderCodeSecurityView(data, aiResult) {
    // 1. Meta
    document.getElementById('scReportId').innerText = `#${data.id} `;
    document.getElementById('scDuration').innerText = `${((data.scan_duration_ms || 0) / 1000).toFixed(2)} s`;

    // 2. Score
    const score = data.threat_score || 0;
    const scoreEl = document.getElementById('scThreatScore');
    scoreEl.innerHTML = `${score} <span class="unit">/100</span>`;

    // Color Logic for Score
    scoreEl.className = "value"; // Reset
    if (score > 80) scoreEl.classList.add("text-neon-red");
    else if (score > 50) scoreEl.classList.add("text-orange-400");
    else scoreEl.classList.add("text-green-400");

    // 3. Risk Badge
    // Note: If no risk level, default to UNKNOWN
    const risk = data.risk_level || 'UNKNOWN';
    const badge = document.getElementById('scRiskBadge');
    badge.innerText = risk;

    // Reset styles
    badge.className = "badge-critical"; // Default class
    badge.style.color = "";
    badge.style.background = "";
    badge.style.borderColor = "";

    if (risk === 'CRITICAL' || risk === 'HIGH') {
        // Keep default red style
    } else if (risk === 'MEDIUM') {
        badge.style.color = "#ff9900";
        badge.style.background = "rgba(255, 153, 0, 0.15)";
        badge.style.borderColor = "rgba(255, 153, 0, 0.3)";
    } else {
        badge.style.color = "#00cc66";
        badge.style.background = "rgba(0, 204, 102, 0.15)";
        badge.style.borderColor = "rgba(0, 204, 102, 0.3)";
    }

    // 4. Stats
    const statsList = document.getElementById('scStatsList');
    let crit = 0, high = 0, med = 0;
    if (data.findings) {
        data.findings.forEach(f => {
            const sev = (f.severity || '').toUpperCase();
            if (sev === 'CRITICAL') crit++;
            if (sev === 'HIGH') high++;
            if (sev === 'MEDIUM') med++;
        });
    }
    statsList.innerHTML = `
                    < li ><span class="dot red"></span> <strong>${crit}</strong> Critical Threats</li >
                <li><span class="dot orange"></span> <strong>${high}</strong> High Threats</li>
                <li><span class="dot green"></span> <strong>${med}</strong> Medium Threats</li>
                `;

    // 5. Remediation Grid
    const grid = document.getElementById('scRemediationGrid');
    grid.innerHTML = '';

    if (aiResult && aiResult.remediation && Array.isArray(aiResult.remediation)) {
        aiResult.remediation.forEach(item => {
            const box = document.createElement('div');
            box.className = "sc-fix-box";

            // Interactive click to copy fix
            box.onclick = () => {
                navigator.clipboard.writeText(`pip install ${item.package}== ${item.fixed_version} `);
                alert('Fix command copied!');
            };
            box.style.cursor = "pointer";

            box.innerHTML = `
                    < div class="fix-header" >
                            <span class="pkg-name">${item.package}</span>
                            <span class="arrow">➜</span>
                            <span class="version-badge">${item.fixed_version || 'Update'}</span>
                        </div >
                        <p class="fix-reason">${item.cve ? '<strong>' + item.cve + '</strong>: ' : ''} ${item.strategy || 'Vulnerability detected.'}</p>
                        <div class="code-snippet">pip install ${item.package}==${item.fixed_version || 'latest'}</div>
                `;
            grid.appendChild(box);
        });
    } else {
        grid.innerHTML = '<div class="text-gray-500 italic p-4">No specific remediation plan generated.</div>';
    }

    // 6. Terminal Log
    const term = document.getElementById('scTerminalContent');
    const counter = document.getElementById('scFindingsCount');

    counter.innerText = `${data.findings ? data.findings.length : 0} Issues`;

    if (data.report) {
        // Colorize the log
        let safeReport = data.report
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") // sanitize HTML
            .replace(/\[CRITICAL\]/g, '<span class="log-crit">[CRITICAL]</span>')
            .replace(/\[HIGH\]/g, '<span class="log-high">[HIGH]</span>')
            .replace(/\[MEDIUM\]/g, '<span class="log-med">[MEDIUM]</span>');

        term.innerHTML = safeReport;
    } else {
        term.innerText = "No raw log available.";
    }
}

// --- USER MANAGEMENT LOGIC ---

async function showUsers() {
    currentTrack = 'users';

    // Update Sidebar Nav UI
    document.querySelectorAll('aside nav button').forEach(b => {
        b.classList.remove('bg-gray-800', 'text-white', 'border-l-4', 'border-brand');
        b.classList.add('text-gray-400');
    });
    const navUsers = document.getElementById('nav-users');
    if (navUsers) {
        navUsers.classList.remove('text-gray-400');
        navUsers.classList.add('bg-gray-800', 'text-white', 'border-l-4', 'border-brand');
    }

    // Update Header
    document.getElementById('trackTitle').textContent = "USER MANAGEMENT";
    document.getElementById('trackDesc').textContent = "Admin Console: Identity & Access Control";

    // Toggle Views
    document.getElementById('inputZone').classList.add('hidden');
    document.getElementById('resultsView').classList.add('hidden');
    document.getElementById('archiveView').classList.add('hidden');
    document.getElementById('stagingView').classList.add('hidden');

    const usersView = document.getElementById('usersView');
    if (usersView) usersView.classList.remove('hidden');

    await fetchUsers();
}

async function fetchUsers() {
    const tbody = document.getElementById('usersTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-gray-500 animate-pulse">LOADING_IDENTITY_DB...</td></tr>';

    try {
        const res = await fetch('/api/users/');
        if (!res.ok) throw new Error("Unauthorized or Failed");
        const users = await res.json();

        tbody.innerHTML = '';
        users.forEach(u => {
            const row = document.createElement('tr');
            row.className = "hover:bg-white/5 transition border-b border-white/5";

            let roleColor = "text-gray-400";
            if (u.role === 'admin') roleColor = "text-brand font-bold";
            if (u.role === 'analyst') roleColor = "text-blue-400";

            row.innerHTML = `
                <td class="p-4 font-mono text-xs text-gray-500">ID - ${u.id}</td>
                <td class="p-4">
                    <div class="text-sm font-bold text-white">${escapeHtml(u.username)}</div>
                    <div class="text-xs text-gray-500">${escapeHtml(u.email)}</div>
                </td>
                <td class="p-4 text-xs ${roleColor} uppercase">${u.role}</td>
                <td class="p-4 text-xs">
                    ${u.is_active ?
                    '<span class="text-success font-bold">ACTIVE</span>' :
                    '<span class="text-alert font-bold">SUSPENDED</span>'}
                </td>
                <td class="p-4 text-xs font-mono">${u.credits_remaining}/50</td>
                <td class="p-4 text-right">
                    <button class="btn-edit-user px-3 py-1 rounded border border-gray-600 hover:border-brand hover:text-white text-gray-400 text-xs transition"
                        data-id="${u.id}" 
                        data-username="${escapeHtml(u.username)}" 
                        data-role="${u.role}" 
                        data-active="${u.is_active}">
                        EDIT
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });

    } catch (e) {
        console.error(e);
        tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-alert">ACCESS_DENIED: Admin privileges required.</td></tr>';
    }
}

// Event Delegation for Edit Button (CSP compliant)
document.addEventListener('click', function (e) {
    if (e.target && e.target.classList.contains('btn-edit-user')) {
        const btn = e.target;
        openEditUser(
            btn.getAttribute('data-id'),
            btn.getAttribute('data-username'),
            btn.getAttribute('data-role'),
            btn.getAttribute('data-active') === 'true'
        );
    }
});

// Global scope for onclick access
window.openEditUser = function (id, username, role, isActive) {
    document.getElementById('editUserId').value = id;
    document.getElementById('editUsername').value = username;
    document.getElementById('editRole').value = role;
    document.getElementById('editActive').checked = isActive;
    document.getElementById('editPassword').value = ''; // Reset password field

    document.getElementById('editUserModal').classList.remove('hidden');
};

function closeEditUserModal() {
    document.getElementById('editUserModal').classList.add('hidden');
}

async function handleEditUserSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('editUserId').value;
    const role = document.getElementById('editRole').value;
    const isActive = document.getElementById('editActive').checked;
    const password = document.getElementById('editPassword').value;

    const payload = {
        role: role,
        is_active: isActive
    };

    if (password && password.trim() !== '') {
        payload.password = password;
    }

    const btn = e.target.querySelector('button[type="submit"]');
    const origText = btn.innerText;
    btn.innerText = "SAVING...";
    btn.disabled = true;

    try {
        const res = await fetch(`/ api / users / ${id} `, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error("Update Failed");

        closeEditUserModal();
        fetchUsers(); // Refresh list
        alert("User Updated Successfully");

    } catch (err) {
        alert("Error updating user: " + err.message);
    } finally {
        btn.innerText = origText;
        btn.disabled = false;
    }
}
// --- Helper Functions ---
function hideAllViews() {
    document.getElementById('inputZone').classList.add('hidden');
    document.getElementById('stagingView').classList.add('hidden');
    document.getElementById('resultsView').classList.add('hidden');
    document.getElementById('archiveView').classList.add('hidden');
    document.getElementById('loader').classList.add('hidden');

    const usersView = document.getElementById('usersView');
    if (usersView) usersView.classList.add('hidden');

    const firewallView = document.getElementById('firewallView');
    if (firewallView) firewallView.classList.add('hidden');
}

// ── METRICS VIEW ─────────────────────────────────────────────────────────────

let _metricsRefreshTimer = null;

async function showMetrics() {
    currentTrack = 'metrics';

    // Nav highlight
    setActiveNav('nav-metrics');

    // Header
    document.getElementById('trackTitle').textContent = 'DETECTION METRICS';
    document.getElementById('trackDesc').textContent = 'Live telemetry · inference latency · false positive samples';

    // Hide all other views
    document.getElementById('inputZone').classList.add('hidden');
    document.getElementById('resultsView').classList.add('hidden');
    document.getElementById('archiveView').classList.add('hidden');
    const usersView = document.getElementById('usersView');
    if (usersView) usersView.classList.add('hidden');
    const firewallView = document.getElementById('firewallView');
    if (firewallView) firewallView.classList.add('hidden');

    document.getElementById('metricsView').classList.remove('hidden');

    // Wire buttons (idempotent — use replaceWith trick to remove old listeners)
    const btnRefresh = document.getElementById('btnRefreshMetrics');
    const btnReset   = document.getElementById('btnResetMetrics');
    const btnFp      = document.getElementById('btnLoadFpSamples');

    btnRefresh.onclick = () => fetchMetricsSnapshot();
    btnReset.onclick   = () => resetMetrics();
    btnFp.onclick      = () => fetchFpSamples();

    // Auto-refresh every 30s
    if (_metricsRefreshTimer) clearInterval(_metricsRefreshTimer);
    _metricsRefreshTimer = setInterval(() => {
        if (currentTrack === 'metrics') fetchMetricsSnapshot();
        else clearInterval(_metricsRefreshTimer);
    }, 30000);

    await fetchMetricsSnapshot();
}

async function fetchMetricsSnapshot() {
    try {
        const res = await fetch('/api/metrics');
        if (!res.ok) { console.error('Metrics fetch failed', res.status); return; }
        const data = await res.json();
        renderMetrics(data);
    } catch (e) {
        console.error('fetchMetricsSnapshot error', e);
    }
}

function renderMetrics(d) {
    const ent = d.entities || {};

    // KPIs
    document.getElementById('mKpiDetected').textContent  = (ent.detected_total  ?? 0).toLocaleString();
    document.getElementById('mKpiValidated').textContent = (ent.after_validation ?? 0).toLocaleString();
    const rejected = (ent.detected_total ?? 0) - (ent.after_validation ?? 0);
    document.getElementById('mKpiRejected').textContent  = Math.max(0, rejected).toLocaleString();
    document.getElementById('mKpiFpBuffer').textContent  = (d.false_positive_buffer_size ?? 0).toLocaleString();
    document.getElementById('metricsLastUpdated').textContent = 'Updated: ' + new Date().toLocaleTimeString();

    // Model Latency bars
    const latency = d.avg_inference_ms || {};
    const latencyEl = document.getElementById('mLatencyBars');
    const models = Object.entries(latency).sort((a, b) => b[1] - a[1]);
    const maxLatency = models.length ? models[0][1] : 1;
    latencyEl.innerHTML = models.length === 0 ? '<p class="text-xs text-gray-600 font-mono">No timing data yet</p>' :
        models.map(([model, ms]) => {
            const pct = Math.min(100, (ms / Math.max(maxLatency, 1)) * 100).toFixed(1);
            const color = ms > 1000 ? 'bg-red-500' : ms > 300 ? 'bg-yellow-400' : 'bg-brand';
            return `<div class="flex items-center gap-3">
                <span class="text-xs font-mono text-gray-400 w-28 shrink-0">${model}</span>
                <div class="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div class="${color} h-full rounded-full transition-all duration-500" style="width:${pct}%"></div>
                </div>
                <span class="text-xs font-mono text-white w-16 text-right">${ms.toFixed(1)} ms</span>
            </div>`;
        }).join('');

    // Rejection breakdown
    const rejMap = ent.rejection_breakdown || {};
    const rejEl  = document.getElementById('mRejectionBars');
    const rejEntries = Object.entries(rejMap).sort((a, b) => b[1] - a[1]);
    const rejMax = rejEntries.length ? rejEntries[0][1] : 1;
    const rejColors = {
        validator_rejection:    'bg-red-500',
        entropy_rejection:      'bg-yellow-400',
        context_gate_rejection: 'bg-blue-400',
        medical_relabel:        'bg-purple-400',
        pre_filter_presidio:    'bg-gray-400',
        pre_filter_ai:          'bg-gray-500',
    };
    rejEl.innerHTML = rejEntries.length === 0 ? '<p class="text-xs text-gray-600 font-mono">No rejections recorded</p>' :
        rejEntries.map(([reason, count]) => {
            const pct = Math.min(100, (count / Math.max(rejMax, 1)) * 100).toFixed(1);
            const clr = rejColors[reason] || 'bg-gray-400';
            return `<div class="flex items-center gap-3">
                <span class="text-[10px] font-mono text-gray-400 w-40 shrink-0 truncate">${reason}</span>
                <div class="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div class="${clr} h-full rounded-full" style="width:${pct}%"></div>
                </div>
                <span class="text-xs font-mono text-white w-10 text-right">${count}</span>
            </div>`;
        }).join('');

    // By Source
    const srcMap = d.by_source || {};
    const srcEl  = document.getElementById('mSourceBars');
    const srcEntries = Object.entries(srcMap).sort((a, b) => (b[1].detected||0) - (a[1].detected||0));
    const srcMax = srcEntries.reduce((m, [, v]) => Math.max(m, v.detected||0), 1);
    srcEl.innerHTML = srcEntries.length === 0 ? '<p class="text-xs text-gray-600 font-mono">No source data yet</p>' :
        srcEntries.map(([src, counts]) => {
            const det = counts.detected || 0;
            const val = counts.validated || 0;
            const pct = Math.min(100, (det / srcMax) * 100).toFixed(1);
            return `<div class="flex items-center gap-3">
                <span class="text-xs font-mono text-gray-400 w-16 shrink-0 capitalize">${src}</span>
                <div class="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div class="bg-brand h-full rounded-full" style="width:${pct}%"></div>
                </div>
                <span class="text-xs font-mono text-gray-400">${val}/${det}</span>
            </div>`;
        }).join('');

    // Per-entity table
    const byType = d.by_type || {};
    const rows = Object.entries(byType).sort((a, b) => (b[1].detected||0) - (a[1].detected||0));
    const tbody = document.getElementById('mEntityTableBody');
    if (rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-gray-600 font-mono text-xs">No entity data yet</td></tr>';
    } else {
        tbody.innerHTML = rows.map(([type, info]) => {
            const det = info.detected || 0;
            const val = info.validated || 0;
            const rate = det > 0 ? Math.round((val / det) * 100) : 0;
            const rateColor = rate >= 80 ? 'text-brand' : rate >= 50 ? 'text-yellow-400' : 'text-red-400';
            const sources = Object.keys(info.by_source || {}).join(', ') || '—';
            return `<tr class="hover:bg-gray-800/30 transition">
                <td class="py-2 pr-4 font-mono text-xs text-gray-300">${type}</td>
                <td class="py-2 pr-4 text-right font-mono">${det.toLocaleString()}</td>
                <td class="py-2 pr-4 text-right font-mono text-brand">${val.toLocaleString()}</td>
                <td class="py-2 pr-4 text-right font-mono ${rateColor}">${rate}%</td>
                <td class="py-2 text-right text-[10px] text-gray-500">${sources}</td>
            </tr>`;
        }).join('');
    }

    // Populate entity type filter dropdown for FP samples
    const fpEntityFilter = document.getElementById('fpEntityFilter');
    const existingTypes = new Set(Array.from(fpEntityFilter.options).map(o => o.value));
    rows.forEach(([type]) => {
        if (!existingTypes.has(type)) {
            const opt = document.createElement('option');
            opt.value = type;
            opt.textContent = type;
            fpEntityFilter.appendChild(opt);
        }
    });
}

async function fetchFpSamples() {
    const reason = document.getElementById('fpReasonFilter').value;
    const entityType = document.getElementById('fpEntityFilter').value;
    let url = '/api/metrics/false-positives?limit=50';
    if (reason) url += `&reason=${encodeURIComponent(reason)}`;
    if (entityType) url += `&entity_type=${encodeURIComponent(entityType)}`;

    try {
        const res = await fetch(url);
        if (!res.ok) { console.error('FP fetch failed', res.status); return; }
        const data = await res.json();
        renderFpSamples(data.samples || []);
    } catch (e) {
        console.error('fetchFpSamples error', e);
    }
}

function renderFpSamples(samples) {
    const tbody = document.getElementById('mFpTableBody');
    if (samples.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="py-6 text-center text-gray-600 font-mono">No samples found</td></tr>';
        return;
    }
    const reasonColors = {
        validator_rejection:    'text-red-400',
        entropy_rejection:      'text-yellow-400',
        context_gate_rejection: 'text-blue-400',
        medical_relabel:        'text-purple-400',
    };
    tbody.innerHTML = samples.map(s => {
        const clr = reasonColors[s.reason] || 'text-gray-400';
        const snippet = (s.context_snippet || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return `<tr class="hover:bg-gray-800/30 transition">
            <td class="py-2 pr-4 font-mono ${clr} whitespace-nowrap">${s.reason || '—'}</td>
            <td class="py-2 pr-4 font-mono text-gray-300 whitespace-nowrap">${s.entity_type || '—'}</td>
            <td class="py-2 pr-4 font-mono text-brand whitespace-nowrap">${s.masked_value || '—'}</td>
            <td class="py-2 text-gray-500 text-[10px] max-w-xs truncate" title="${snippet}">${snippet || '—'}</td>
        </tr>`;
    }).join('');
}

async function resetMetrics() {
    if (!confirm('Reset all detection metrics counters and FP buffer? This cannot be undone.')) return;
    try {
        const res = await fetch('/api/metrics/reset', { method: 'POST' });
        if (res.ok) {
            await fetchMetricsSnapshot();
            document.getElementById('mFpTableBody').innerHTML =
                '<tr><td colspan="4" class="py-6 text-center text-gray-600 font-mono">Buffer cleared — click LOAD to refresh</td></tr>';
        }
    } catch (e) {
        console.error('resetMetrics error', e);
    }
}

// ─────────────────────────────────────────────────────────────────────────────

function setActiveNav(activeId) {
    document.querySelectorAll('aside nav button').forEach(b => {
        const isTarget = b.id === activeId;
        if (isTarget) {
            b.classList.add('bg-gray-800', 'text-white', 'border-l-4', 'border-brand');
            b.classList.remove('text-gray-400');
        } else {
            b.classList.remove('bg-gray-800', 'text-white', 'border-l-4', 'border-brand');
            b.classList.add('text-gray-400');
        }
    });
}
