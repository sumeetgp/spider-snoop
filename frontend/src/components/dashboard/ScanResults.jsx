import React from 'react';
import CodeSecurityReport from './CodeSecurityReport';
import { AlertCircle, CheckCircle, BrainCircuit } from 'lucide-react';

const ScanResults = ({ type, data, onReset }) => {
    // 'data' would contain the scan result JSON
    // 'type' is the track type: 'sentinel', 'guardian', 'vision', 'security'

    if (type === 'security') {
        return <CodeSecurityReport data={data} />;
    }

    const { score, verdict, summary, findings } = data || {
        score: 0,
        verdict: 'PENDING',
        summary: 'Analysis running...',
        findings: []
    };

    return (
        <div className="space-y-6 animate-fade-in">
            {/* Scan Complete Header with Actions */}
            <div className="flex justify-between items-center bg-gray-800/50 p-4 rounded-xl border border-gray-700">
                <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                    <h2 className="text-lg font-bold text-white tracking-wide">SCAN COMPLETE</h2>
                </div>
                <div className="flex gap-2">
                    <button
                        onClick={onReset || (() => window.location.reload())}
                        className="bg-[#88FFFF] hover:bg-[#66DDDD] text-gray-900 px-4 py-2 rounded-lg text-sm font-bold transition flex items-center gap-2 shadow-lg hover:shadow-[#88FFFF]/20"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                        </svg>
                        SCAN NEXT TARGET
                    </button>
                </div>
            </div>

            {/* Protection Flow Visualization */}
            <div className="glass-panel p-4 rounded-xl flex items-center justify-between border border-border">
                <div className="flex items-center gap-4 text-xs font-mono w-full">
                    {/* Regex Analysis */}
                    <div className="flex flex-col items-center gap-2">
                        <div className="w-10 h-10 rounded-full bg-gray-800 flex items-center justify-center border border-brand text-brand">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                            </svg>
                        </div>
                        <span className="text-gray-500">REGEX_ANALYSIS</span>
                    </div>
                    <div className="h-0.5 flex-1 bg-gray-800 mx-2 relative">
                        <div className="absolute inset-0 bg-brand/50 w-full animate-pulse"></div>
                    </div>

                    {/* AI Analysis */}
                    <div className="flex flex-col items-center gap-2">
                        <div className="w-10 h-10 rounded-full bg-gray-800 flex items-center justify-center border border-brand text-brand">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                            </svg>
                        </div>
                        <span className="text-gray-500">AI_ANALYSIS</span>
                    </div>
                    <div className="h-0.5 flex-1 bg-gray-800 mx-2 relative">
                        <div className="absolute inset-0 bg-brand/50 w-full animate-pulse"></div>
                    </div>

                    {/* Context Scan */}
                    <div className="flex flex-col items-center gap-2">
                        <div className="w-10 h-10 rounded-full bg-gray-800 flex items-center justify-center border border-brand text-brand">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                            </svg>
                        </div>
                        <span className="text-gray-500">CONTEXT_SCAN</span>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Score Card */}
                <div className="glass-panel p-6 rounded-2xl col-span-1 bg-[#161B22]/70 border border-[#30363d]">
                    <p className="text-xs text-gray-500 uppercase tracking-widest font-bold mb-1">Threat Score</p>
                    <p className="text-5xl font-black text-white">{score}<span className="text-xl text-gray-600">/100</span></p>
                    <div className={`mt-4 p-2 rounded text-[11px] font-mono border ${verdict === 'CLEAN' ? 'border-green-500/30 text-green-400 bg-green-500/10' :
                        verdict === 'MALICIOUS' ? 'border-red-500/30 text-red-400 bg-red-500/10' :
                            'border-gray-600 text-gray-400'
                        }`}>
                        {verdict ? verdict.replace('VERDICT_', '') : 'UNKNOWN'}
                    </div>
                </div>

                {/* Intelligence Hub */}
                <div className="glass-panel p-6 rounded-2xl col-span-2 relative overflow-hidden flex flex-col bg-[#161B22]/70 border border-[#30363d]">
                    <div className="flex items-center justify-between mb-4">
                        <div className="flex gap-2">
                            <span className="text-[10px] font-mono bg-gray-800 px-2 py-1 rounded text-gray-400">ID: <span className="text-white">{data?.id || '---'}</span></span>
                            <span className="text-[10px] font-mono bg-gray-800 px-2 py-1 rounded text-gray-400">TIME: <span className="text-white">{data?.duration || '0'}</span>ms</span>
                        </div>
                    </div>

                    <div className="h-full overflow-y-auto">

                        {/* Summary / Reason */}
                        {summary && !data?.aiInsight && (
                            <p className="text-sm text-gray-300 mb-4 font-light leading-relaxed">
                                {summary}
                            </p>
                        )}

                        {/* AI Insight Structure */}
                        {data?.aiInsight && (
                            <div className="grid grid-cols-1 gap-4">
                                {/* Header */}
                                <div className="flex items-center gap-2 mb-1 text-[#88FFFF] border-b border-gray-700/50 pb-2">
                                    <BrainCircuit className="w-4 h-4" />
                                    <span className="text-xs font-bold uppercase tracking-wider">Security Analysis Hub (v2)</span>
                                </div>

                                {/* 1. Threat Analysis (All Findings) */}
                                <div className="bg-gray-800/50 rounded p-3 border border-gray-700">
                                    <div className="text-[10px] uppercase text-gray-500 font-bold mb-2">Threat Analysis</div>
                                    <div className="text-xs text-gray-300 space-y-1 max-h-48 overflow-y-auto pr-2 custom-scrollbar">
                                        {findings && findings.length > 0 ? (
                                            findings.map((f, i) => (
                                                <div key={i} className="flex justify-between items-center py-0.5 border-b border-gray-700/30 last:border-0">
                                                    <span>• {f.type}</span>
                                                    <span className={`${f.severity === 'CRITICAL' ? 'text-red-500' : f.severity === 'HIGH' ? 'text-orange-500' : 'text-yellow-500'} font-mono text-[10px]`}>{f.severity}</span>
                                                </div>
                                            ))
                                        ) : (
                                            <span className="text-gray-500 italic">No specific patterns matched.</span>
                                        )}
                                    </div>
                                </div>

                                {/* 2. AI Assessment (Verdict & Confidence) */}
                                <div className="bg-gray-800/50 rounded p-3 border border-gray-700">
                                    <div className="text-[10px] uppercase text-gray-500 font-bold mb-2">AI Assessment</div>
                                    <div className="flex flex-col gap-2">
                                        <div className="text-xs text-gray-300">{data.aiInsight.split('(')[0] || data.aiInsight}</div>
                                        {/* Parse Confidence from string */}
                                        {(() => {
                                            const match = data.aiInsight.match(/Confidence:\s*(\d+(\.\d+)?)/);
                                            const confidence = match ? parseFloat(match[1]) : 0;
                                            const percent = Math.round(confidence * 100);
                                            // Handle edge case where confidence is already percent (unlikely in this backend but possible)
                                            const displayPercent = confidence <= 1 ? percent : Math.round(confidence);

                                            return (
                                                <div className="w-full">
                                                    <div className="flex justify-between text-[10px] uppercase text-gray-500 mb-1">
                                                        <span>Confidence Score</span>
                                                        <span className="font-mono text-white">{displayPercent}%</span>
                                                    </div>
                                                    <div className="w-full h-1.5 bg-gray-900 rounded-full overflow-hidden">
                                                        <div
                                                            className={`h-full transition-all duration-500 ${verdict.includes('BLOCK') ? 'bg-red-500' : 'bg-green-500'}`}
                                                            style={{ width: `${displayPercent}%` }}
                                                        ></div>
                                                    </div>
                                                </div>
                                            );
                                        })()}
                                    </div>
                                </div>

                                {/* 3. Recommendation */}
                                <div className="mt-1 pt-3 border-t border-gray-700/50">
                                    <div className="flex items-center justify-between">
                                        <span className="text-xs font-bold text-gray-400 uppercase">Recommendation</span>
                                        <span className={`text-sm font-bold ${verdict && (verdict.includes('BLOCK') || verdict.includes('REVIEW')) ? 'text-red-400' : 'text-green-400'}`}>
                                            {verdict && verdict.includes('BLOCK') ? '🚫 BLOCK TRANSFER' : (verdict && verdict.includes('REVIEW')) ? '⚠️ REVIEW FINDINGS' : '✅ ALLOW TRANSFER'}
                                        </span>
                                    </div>
                                </div>

                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Findings Table */}
            <div className="glass-panel rounded-2xl overflow-hidden border border-[#30363d] bg-[#161B22]/70">
                <div className="p-4 border-b border-[#30363d] bg-gray-800/30 flex justify-between items-center">
                    <h2 className="text-sm font-bold text-white">Engine Findings</h2>
                    <button className="text-xs text-[#88FFFF] hover:underline font-mono">[COPY_JSON]</button>
                </div>
                {findings && findings.length > 0 ? (
                    <table className="w-full text-left text-xs">
                        <thead className="bg-gray-900/50 text-gray-500 uppercase">
                            <tr>
                                <th className="p-4">Type</th>
                                <th className="p-4">Severity</th>
                                <th className="p-4">Detail</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-[#30363d] text-gray-300">
                            {findings.map((finding, idx) => (
                                <tr key={idx} className="hover:bg-white/5 transition">
                                    <td className="p-4 font-mono font-bold">{finding.type}</td>
                                    <td className="p-4">
                                        <span className={`px-2 py-1 rounded text-[10px] font-bold ${finding.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                                            finding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                                                'bg-gray-700 text-gray-400'
                                            }`}>{finding.severity}</span>
                                    </td>
                                    <td className="p-4 font-mono opacity-80">{finding.detail}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                ) : (
                    <div className="text-center p-8 text-gray-500">
                        &gt;&gt; NO THREATS DETECTED. SYSTEM CLEAN.
                    </div>
                )}
            </div>
        </div>
    );
};

export default ScanResults;
