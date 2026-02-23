import React, { useEffect, useState } from 'react';
import { Activity, ShieldAlert, FileSearch, ShieldCheck, Clock, ChevronDown, ChevronUp, ChevronLeft, ChevronRight } from 'lucide-react';

const OverviewTrack = () => {
    const [stats, setStats] = useState(null);
    const [scans, setScans] = useState([]);
    const [loadingStats, setLoadingStats] = useState(true);
    const [loadingScans, setLoadingScans] = useState(true);

    // Pagination
    const [page, setPage] = useState(1);
    const limit = 10;
    const [expandedRows, setExpandedRows] = useState({});

    const fetchStats = async () => {
        try {
            const res = await fetch('/api/scans/stats', {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token')}` }
            });
            if (res.ok) {
                const data = await res.json();
                setStats(data);
            }
        } catch (error) {
            console.error("Failed to fetch stats", error);
        } finally {
            setLoadingStats(false);
        }
    };

    const fetchScans = async () => {
        setLoadingScans(true);
        try {
            const skip = (page - 1) * limit;
            const res = await fetch(`/api/scans/?limit=${limit}&skip=${skip}&days=7`, {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token')}` }
            });
            if (res.ok) {
                const data = await res.json();
                setScans(data);
            }
        } catch (error) {
            console.error("Failed to fetch scans", error);
        } finally {
            setLoadingScans(false);
        }
    };

    useEffect(() => {
        fetchStats();
    }, []);

    useEffect(() => {
        fetchScans();
    }, [page]);

    const toggleRow = (id) => {
        setExpandedRows(prev => ({
            ...prev,
            [id]: !prev[id]
        }));
    };

    if (loadingStats) return <div className="text-gray-400 p-8">Loading dashboard analytics...</div>;
    if (!stats) return <div className="text-red-400 p-8">Failed to load analytics.</div>;

    const totalRisks = (stats.scans_by_risk?.CRITICAL || 0) + (stats.scans_by_risk?.HIGH || 0);
    const safeScans = stats.scans_by_risk?.LOW || 0;

    // Calculate percentages for bar chart
    const total = stats.total_scans || 1; // avoid div by zero
    const critical = stats.scans_by_risk?.CRITICAL || 0;
    const high = stats.scans_by_risk?.HIGH || 0;
    const medium = stats.scans_by_risk?.MEDIUM || 0;
    const low = stats.scans_by_risk?.LOW || 0;

    return (
        <div className="space-y-6 animate-fade-in pb-10">
            {/* Header */}
            <div>
                <h2 className="text-2xl font-black text-white tracking-tight">SECURITY POSTURE</h2>
                <p className="text-gray-400 text-sm">Real-time overview of your security landscape.</p>
            </div>

            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-[#0D1117] border border-[#30363d] p-4 rounded-xl flex items-center gap-4">
                    <div className="p-3 bg-blue-500/10 rounded-lg text-blue-400">
                        <Activity className="w-6 h-6" />
                    </div>
                    <div>
                        <div className="text-sm text-gray-400">Total Scans</div>
                        <div className="text-2xl font-black text-white">{stats.total_scans}</div>
                    </div>
                </div>

                <div className="bg-[#0D1117] border border-[#30363d] p-4 rounded-xl flex items-center gap-4">
                    <div className="p-3 bg-red-500/10 rounded-lg text-red-400">
                        <ShieldAlert className="w-6 h-6" />
                    </div>
                    <div>
                        <div className="text-sm text-gray-400">Threats Detected</div>
                        <div className="text-2xl font-black text-white">{totalRisks}</div>
                    </div>
                </div>

                <div className="bg-[#0D1117] border border-[#30363d] p-4 rounded-xl flex items-center gap-4">
                    <div className="p-3 bg-green-500/10 rounded-lg text-green-400">
                        <ShieldCheck className="w-6 h-6" />
                    </div>
                    <div>
                        <div className="text-sm text-gray-400">Clean Files</div>
                        <div className="text-2xl font-black text-white">{safeScans}</div>
                    </div>
                </div>

                <div className="bg-[#0D1117] border border-[#30363d] p-4 rounded-xl flex items-center gap-4">
                    <div className="p-3 bg-purple-500/10 rounded-lg text-purple-400">
                        <Clock className="w-6 h-6" />
                    </div>
                    <div>
                        <div className="text-sm text-gray-400">Avg Scan Time</div>
                        <div className="text-2xl font-black text-white">{Math.round(stats.avg_scan_duration_ms)}ms</div>
                    </div>
                </div>
            </div>

            {/* Charts Section */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Risk Distribution */}
                <div className="lg:col-span-2 bg-[#0D1117] border border-[#30363d] rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-6">Threat Distribution</h3>

                    <div className="space-y-4">
                        {/* Critical */}
                        <div>
                            <div className="flex justify-between text-xs text-gray-400 mb-1">
                                <span className="text-red-400 font-bold">CRITICAL</span>
                                <span>{critical} ({Math.round(critical / total * 100)}%)</span>
                            </div>
                            <div className="w-full bg-gray-800 rounded-full h-2">
                                <div className="bg-red-500 h-2 rounded-full transition-all duration-1000" style={{ width: `${(critical / total) * 100}%` }}></div>
                            </div>
                        </div>

                        {/* High */}
                        <div>
                            <div className="flex justify-between text-xs text-gray-400 mb-1">
                                <span className="text-orange-400 font-bold">HIGH</span>
                                <span>{high} ({Math.round(high / total * 100)}%)</span>
                            </div>
                            <div className="w-full bg-gray-800 rounded-full h-2">
                                <div className="bg-orange-500 h-2 rounded-full transition-all duration-1000" style={{ width: `${(high / total) * 100}%` }}></div>
                            </div>
                        </div>

                        {/* Medium */}
                        <div>
                            <div className="flex justify-between text-xs text-gray-400 mb-1">
                                <span className="text-yellow-400 font-bold">MEDIUM</span>
                                <span>{medium} ({Math.round(medium / total * 100)}%)</span>
                            </div>
                            <div className="w-full bg-gray-800 rounded-full h-2">
                                <div className="bg-yellow-500 h-2 rounded-full transition-all duration-1000" style={{ width: `${(medium / total) * 100}%` }}></div>
                            </div>
                        </div>

                        {/* Low */}
                        <div>
                            <div className="flex justify-between text-xs text-gray-400 mb-1">
                                <span className="text-green-400 font-bold">LOW / SAFE</span>
                                <span>{low} ({Math.round(low / total * 100)}%)</span>
                            </div>
                            <div className="w-full bg-gray-800 rounded-full h-2">
                                <div className="bg-green-500 h-2 rounded-full transition-all duration-1000" style={{ width: `${(low / total) * 100}%` }}></div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Status Summary */}
                <div className="bg-[#0D1117] border border-[#30363d] rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-6">Action Summary</h3>
                    <div className="space-y-4">
                        {Object.entries(stats.scans_by_status || {}).map(([key, value]) => (
                            <div key={key} className="flex items-center justify-between p-3 bg-gray-800/30 rounded border border-gray-700">
                                <span className="text-sm font-mono text-gray-300">{key}</span>
                                <span className="text-sm font-bold text-[#88FFFF]">{value}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Recent Activity Table */}
            <div className="bg-[#0D1117] border border-[#30363d] rounded-xl overflow-hidden">
                <div className="p-6 border-b border-[#30363d] flex justify-between items-center">
                    <div>
                        <h3 className="text-lg font-bold text-white">Recent Activity</h3>
                        <p className="text-xs text-gray-500 mt-1">Showing last 7 days</p>
                    </div>
                    <div className="flex gap-2">
                        <button
                            onClick={() => setPage(p => Math.max(1, p - 1))}
                            disabled={page === 1}
                            className="p-2 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded text-gray-400 transition"
                        >
                            <ChevronLeft className="w-4 h-4" />
                        </button>
                        <span className="px-3 py-2 bg-gray-900 border border-gray-700 rounded text-xs font-mono text-gray-400 flex items-center">
                            Page {page}
                        </span>
                        <button
                            onClick={() => setPage(p => p + 1)}
                            disabled={scans.length < limit}
                            className="p-2 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded text-gray-400 transition"
                        >
                            <ChevronRight className="w-4 h-4" />
                        </button>
                    </div>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="bg-[#161B22] text-xs uppercase text-gray-400 font-bold">
                                <th className="p-4 w-10"></th>
                                <th className="p-4">ID</th>
                                <th className="p-4">User</th>
                                <th className="p-4">Timestamp</th>
                                <th className="p-4">Source</th>
                                <th className="p-4">Verdict</th>
                                <th className="p-4">Risk</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-[#30363d]">
                            {loadingScans ? (
                                <tr><td colSpan="6" className="p-8 text-center text-gray-500">Loading scans...</td></tr>
                            ) : scans.map((scan) => (
                                <React.Fragment key={scan.id}>
                                    <tr className={`hover:bg-white/5 transition text-sm cursor-pointer ${expandedRows[scan.id] ? 'bg-white/5' : ''}`} onClick={() => toggleRow(scan.id)}>
                                        <td className="p-4 text-gray-500">
                                            {expandedRows[scan.id] ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                                        </td>
                                        <td className="p-4 font-mono text-gray-500">#{scan.id}</td>
                                        <td className="p-4 text-gray-300">
                                            {scan.user ? (
                                                <span>ID: {scan.user.id} - {scan.user.email || scan.user.username}</span>
                                            ) : (
                                                'Unknown'
                                            )}
                                        </td>
                                        <td className="p-4 text-gray-300">{new Date(scan.created_at).toLocaleString()}</td>
                                        <td className="p-4 text-gray-300 truncate max-w-[200px]">{scan.source}</td>
                                        <td className="p-4">
                                            <span className={`px-2 py-1 rounded text-[10px] font-bold border ${scan.verdict?.includes('BLOCK') ? 'border-red-500/30 bg-red-500/10 text-red-400' :
                                                scan.verdict?.includes('SAFE') || scan.verdict?.includes('ALLOW') ? 'border-green-500/30 bg-green-500/10 text-green-400' :
                                                    'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
                                                }`}>
                                                {scan.verdict?.split(':')[0]?.replace('VERDICT_', '') || 'UNKNOWN'}
                                            </span>
                                        </td>
                                        <td className="p-4">
                                            <span className={`font-mono font-bold ${(scan.risk_level === 'critical' || scan.risk_level === 'CRITICAL') ? 'text-red-500' :
                                                (scan.risk_level === 'high' || scan.risk_level === 'HIGH') ? 'text-orange-500' :
                                                    (scan.risk_level === 'medium' || scan.risk_level === 'MEDIUM') ? 'text-yellow-500' :
                                                        'text-green-500'
                                                }`}>
                                                {(scan.risk_level || 'UNKNOWN').toUpperCase()}
                                            </span>
                                        </td>
                                    </tr>
                                    {/* Expanded Detail Row */}
                                    {expandedRows[scan.id] && (
                                        <tr className="bg-[#0D1117]/50 animate-fade-in">
                                            <td colSpan="7" className="p-4 border-b border-[#30363d]">
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                                                    {/* Full Verdict */}
                                                    <div className="p-3 bg-gray-800 rounded border border-gray-700 col-span-1">
                                                        <div className="text-gray-500 mb-1 uppercase font-bold">Full Verdict</div>
                                                        <div className="font-mono text-gray-300 break-all">{scan.verdict}</div>
                                                    </div>

                                                    {/* Findings List (Grouped) */}
                                                    <div className="col-span-1 p-3 bg-gray-800 rounded border border-gray-700">
                                                        <div className="text-gray-500 mb-2 uppercase font-bold">Findings Detail</div>
                                                        {scan.findings && scan.findings.length > 0 ? (
                                                            <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
                                                                {(() => {
                                                                    // Group findings by type and sum the counts
                                                                    const groupedFindings = scan.findings.reduce((acc, current) => {
                                                                        const type = current.type || 'unknown';
                                                                        const count = current.count || 1;
                                                                        acc[type] = (acc[type] || 0) + count;
                                                                        return acc;
                                                                    }, {});

                                                                    return Object.entries(groupedFindings).map(([type, totalCount], i) => (
                                                                        <div key={i} className="flex justify-between items-center p-1.5 bg-gray-900 border border-gray-700/50 rounded">
                                                                            <span className="text-blue-400 font-bold truncate pr-2" title={type}>{type}</span>
                                                                            <span className="text-gray-400 bg-gray-800 px-1.5 py-0.5 rounded text-[10px] whitespace-nowrap">x{totalCount}</span>
                                                                        </div>
                                                                    ));
                                                                })()}
                                                            </div>
                                                        ) : (
                                                            <span className="text-gray-500 italic">No specific findings recorded.</span>
                                                        )}
                                                    </div>

                                                    {/* AI Analysis & Remediation */}
                                                    {scan.ai_analysis && (
                                                        <div className="col-span-1 md:col-span-2 p-3 bg-gray-800 rounded border border-gray-700">
                                                            <div className="text-gray-500 mb-2 uppercase font-bold">AI Analysis</div>
                                                            <div className="font-mono text-gray-300">
                                                                {(() => {
                                                                    try {
                                                                        const ai = typeof scan.ai_analysis === 'string' ? JSON.parse(scan.ai_analysis) : scan.ai_analysis;
                                                                        const { remediation, ...restAi } = ai;

                                                                        return (
                                                                            <div className="space-y-4">
                                                                                {/* General AI fields */}
                                                                                <ul className="space-y-1">
                                                                                    {Object.entries(restAi).map(([k, v]) => (
                                                                                        <li key={k}><span className="text-gray-500">{k}:</span> {typeof v === 'object' ? JSON.stringify(v) : v}</li>
                                                                                    ))}
                                                                                </ul>

                                                                                {/* Remediation Table for CVEs */}
                                                                                {remediation && Array.isArray(remediation) && remediation.length > 0 && (
                                                                                    <div className="mt-4 border border-gray-700 rounded-lg overflow-hidden">
                                                                                        <div className="bg-gray-900 px-3 py-2 text-sm font-bold text-gray-300 border-b border-gray-700">Recommended Remediations</div>
                                                                                        <div className="overflow-x-auto">
                                                                                            <table className="w-full text-left text-xs">
                                                                                                <thead className="bg-[#161B22] text-gray-400">
                                                                                                    <tr>
                                                                                                        <th className="p-2 border-b border-gray-700">Package</th>
                                                                                                        <th className="p-2 border-b border-gray-700">Severity</th>
                                                                                                        <th className="p-2 border-b border-gray-700 min-w-[200px]">CVEs</th>
                                                                                                        <th className="p-2 border-b border-gray-700 hidden sm:table-cell">Current</th>
                                                                                                        <th className="p-2 border-b border-gray-700">Target</th>
                                                                                                        <th className="p-2 border-b border-gray-700">Action</th>
                                                                                                    </tr>
                                                                                                </thead>
                                                                                                <tbody className="divide-y divide-gray-700/50 bg-gray-800/50">
                                                                                                    {remediation.map((item, idx) => (
                                                                                                        <tr key={idx} className="hover:bg-gray-750">
                                                                                                            <td className="p-2 font-bold text-white">{item.package}</td>
                                                                                                            <td className="p-2">
                                                                                                                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${item.severity === 'CRITICAL' || item.severity === 'HIGH' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                                                                                                                    {item.severity || 'UNKNOWN'}
                                                                                                                </span>
                                                                                                            </td>
                                                                                                            <td className="p-2 text-red-400 break-words max-w-xs">{item.cve}</td>
                                                                                                            <td className="p-2 text-gray-400 hidden sm:table-cell truncate max-w-[150px]" title={item.current_version}>{item.current_version}</td>
                                                                                                            <td className="p-2 text-green-400 font-mono">{item.fixed_version}</td>
                                                                                                            <td className="p-2">
                                                                                                                {item.link ? (
                                                                                                                    <a href={item.link} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">{item.action || 'Update'}</a>
                                                                                                                ) : (
                                                                                                                    <span className="text-gray-300">{item.action || 'Update'}</span>
                                                                                                                )}
                                                                                                            </td>
                                                                                                        </tr>
                                                                                                    ))}
                                                                                                </tbody>
                                                                                            </table>
                                                                                        </div>
                                                                                    </div>
                                                                                )}
                                                                            </div>
                                                                        );
                                                                    } catch (e) {
                                                                        return <div className="max-h-32 overflow-y-auto">{scan.ai_analysis}</div>;
                                                                    }
                                                                })()}
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                </React.Fragment>
                            ))}
                            {!loadingScans && scans.length === 0 && (
                                <tr>
                                    <td colSpan="7" className="p-8 text-center text-gray-500 italic">No scans found in the last 7 days.</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default OverviewTrack;
