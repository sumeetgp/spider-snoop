import React from 'react';
import { AlertCircle, ShieldCheck, CheckCircle, Package } from 'lucide-react';

const CodeSecurityReport = ({ data }) => {
    // Extract remediation from API response
    const remediationPlan = data?.ai_analysis?.remediation || data?.remediation || [];
    const source = data?.source || "";

    const getEcosystemUrl = (pkg, version) => {
        if (!pkg || !version) return "#";
        // Heuristic based on source file
        if (source.includes('requirements.txt') || source.includes('pyproject.toml') || source.includes('.py')) {
            return `https://pypi.org/project/${pkg}/${version}/`;
        }
        if (source.includes('package.json') || source.includes('yarn.lock') || source.includes('.js') || source.includes('.ts')) {
            return `https://www.npmjs.com/package/${pkg}/v/${version}`;
        }
        // Fallback
        return `https://google.com/search?q=${pkg}+${version}+security+fix`;
    };

    // Debug logging
    console.warn('=== CODE SECURITY DEBUG ===');
    console.warn('Has data:', !!data);
    console.warn('Has ai_analysis:', !!data?.ai_analysis);
    console.warn('Has remediation:', !!data?.ai_analysis?.remediation);
    console.warn('Remediation count:', remediationPlan.length);
    console.warn('Full remediation:', remediationPlan);
    console.warn('==========================');

    return (
        <div className="space-y-6 animate-fade-in">
            {/* Flow Visualization */}
            <div className="glass-panel p-4 rounded-xl flex items-center justify-between border border-[#30363d] bg-[#161B22]/50">
                <div className="flex items-center gap-4 text-xs font-mono w-full">
                    <div className="flex flex-col items-center gap-2">
                        <div className="w-10 h-10 rounded-full bg-gray-800 flex items-center justify-center border border-brand text-brand">
                            <Package className="w-5 h-5" />
                        </div>
                        <span className="text-gray-500">TRIVY_SCAN</span>
                    </div>
                    <div className="h-0.5 flex-1 bg-gray-800 mx-2 relative">
                        <div className="absolute inset-0 bg-[#88FFFF]/50 w-full animate-pulse"></div>
                    </div>
                    <div className="flex flex-col items-center gap-2">
                        <div className="w-10 h-10 rounded-full bg-gray-800 flex items-center justify-center border border-brand text-brand">
                            <ShieldCheck className="w-5 h-5" />
                        </div>
                        <span className="text-gray-500">OSV_AUDIT</span>
                    </div>
                    <div className="h-0.5 flex-1 bg-gray-800 mx-2 relative">
                        <div className="absolute inset-0 bg-[#88FFFF]/50 w-full animate-pulse"></div>
                    </div>
                    <div className="flex flex-col items-center gap-2">
                        <div className="w-10 h-10 rounded-full bg-gray-800 flex items-center justify-center border border-brand text-brand">
                            <CheckCircle className="w-5 h-5" />
                        </div>
                        <span className="text-gray-500">AI_REMEDIATION</span>
                    </div>
                </div>
            </div>

            {/* Remediation Panel */}
            <div className="glass-panel rounded-2xl p-6 border border-gray-700/50 bg-[#161B22]/70">
                <div className="flex items-center gap-2 mb-4 text-[#88FFFF]">
                    <ShieldCheck className="w-5 h-5" />
                    <span className="text-sm font-bold uppercase tracking-wider">Recommended Remediation Plan</span>
                </div>

                <div className="overflow-hidden rounded-xl border border-gray-700/50 bg-gray-900/30">
                    <table className="w-full text-left text-sm">
                        <thead className="bg-gray-800/80 text-gray-400 uppercase text-xs tracking-wider">
                            <tr>
                                <th className="p-4 font-semibold w-1/4">Package / Version</th>
                                <th className="p-4 font-semibold w-1/4">CVEs</th>
                                <th className="p-4 font-semibold w-1/6">Severity</th>
                                <th className="p-4 font-semibold w-1/6">Fixed In</th>
                                <th className="p-4 font-semibold w-1/6">Action</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800 text-gray-300">
                            {remediationPlan.length > 0 ? remediationPlan.map((item, idx) => {
                                // Heuristic: If fixed_version looks like an instruction ("Revoke", "Rotate"), move to Action
                                const isInstruction = item.fixed_version && (item.fixed_version.includes('Revoke') || item.fixed_version.includes('Rotate') || item.fixed_version.includes('Manual'));

                                return (
                                    <tr key={idx} className="hover:bg-white/5 transition">
                                        <td className="p-4 font-mono font-bold text-white max-w-xs break-all">
                                            {item.package} <span className="text-gray-500 text-xs block">{item.current_version}</span>
                                        </td>
                                        <td className="p-4 text-red-400 font-mono text-xs max-w-[150px]">{item.cve}</td>
                                        <td className="p-4"><span className={`px-2 py-1 rounded text-xs font-bold border ${item.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                                            item.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                                                'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                                            }`}>{item.severity}</span></td>
                                        <td className="p-4 font-mono text-green-400 text-xs">
                                            {isInstruction ? 'N/A' : item.fixed_version}
                                        </td>
                                        <td className="p-4">
                                            {isInstruction ? (
                                                <span className="text-orange-400 text-xs font-bold border border-orange-500/30 px-2 py-1 rounded uppercase">{item.fixed_version}</span>
                                            ) : (
                                                <a
                                                    href={getEcosystemUrl(item.package, item.fixed_version)}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="text-[#88FFFF] hover:underline text-xs font-bold flex items-center gap-1"
                                                >
                                                    [VIEW_FIX]
                                                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                                                </a>
                                            )}
                                        </td>
                                    </tr>
                                )
                            }) : (
                                <tr>
                                    <td colSpan="5" className="p-8 text-center text-gray-500">NO VULNERABILITIES DETECTED OR REMEDIATED</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default CodeSecurityReport;
