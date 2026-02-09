import React from 'react';
import { useNavigate } from 'react-router-dom';

const AIFirewall = () => {
    const navigate = useNavigate();

    return (
        <div className="min-h-screen bg-[#0D1117] text-[#C9D1D9] p-8">
            {/* Header */}
            <div className="max-w-7xl mx-auto mb-8">
                <div className="flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-black text-white mb-2">AI FIREWALL</h1>
                        <p className="text-sm text-gray-400 font-mono">// LLM_GUARD_&_AUDIT</p>
                    </div>
                    <button
                        onClick={() => navigate('/dashboard')}
                        className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded border border-[#30363d] transition"
                    >
                        ← BACK TO DASHBOARD
                    </button>
                </div>
            </div>

            {/* Coming Soon Content */}
            <div className="max-w-4xl mx-auto">
                <div className="glass-panel rounded-xl p-12 text-center">
                    <div className="text-6xl mb-6">🛡️</div>
                    <h2 className="text-2xl font-bold text-white mb-4">COMING SOON</h2>
                    <p className="text-gray-400 mb-8 max-w-2xl mx-auto">
                        The AI Firewall admin console is currently under development.
                        This feature will provide LLM Guard configuration, audit logs,
                        and real-time monitoring of AI-powered security controls.
                    </p>

                    {/* Feature Preview */}
                    <div className="grid md:grid-cols-3 gap-6 mt-12 text-left">
                        <div className="bg-black/30 border border-[#30363d] rounded-lg p-6">
                            <div className="text-[#88FFFF] mb-3">
                                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                            </div>
                            <h3 className="font-bold text-white mb-2">LLM Guard Rules</h3>
                            <p className="text-sm text-gray-400">
                                Configure prompt injection detection, content filtering, and output validation rules.
                            </p>
                        </div>

                        <div className="bg-black/30 border border-[#30363d] rounded-lg p-6">
                            <div className="text-[#88FFFF] mb-3">
                                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                                </svg>
                            </div>
                            <h3 className="font-bold text-white mb-2">Audit Logs</h3>
                            <p className="text-sm text-gray-400">
                                Review all AI interactions, blocked requests, and security events in real-time.
                            </p>
                        </div>

                        <div className="bg-black/30 border border-[#30363d] rounded-lg p-6">
                            <div className="text-[#88FFFF] mb-3">
                                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                                </svg>
                            </div>
                            <h3 className="font-bold text-white mb-2">Analytics</h3>
                            <p className="text-sm text-gray-400">
                                Monitor threat trends, model performance, and compliance metrics.
                            </p>
                        </div>
                    </div>

                    {/* ICAP Link */}
                    <div className="mt-12 pt-8 border-t border-[#30363d]">
                        <p className="text-sm text-gray-400 mb-4">
                            In the meantime, you can configure ICAP integration for network-level protection:
                        </p>
                        <a
                            href="/icap"
                            className="inline-block px-6 py-3 bg-[#88FFFF] text-black font-bold rounded hover:bg-[#66DDDD] transition"
                        >
                            VIEW ICAP DOCUMENTATION →
                        </a>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AIFirewall;
