import React from 'react';

const Sidebar = ({ activeTrack, setActiveTrack, credits, onLogout, user }) => {

    const SidebarButton = ({ id, icon, title, subtitle }) => {
        const active = activeTrack === id;
        return (
            <button
                onClick={() => setActiveTrack(id)}
                className={`w-full text-left p-3 rounded hover:bg-gray-800 text-sm font-bold transition flex items-center gap-3 ${active ? 'bg-[#88FFFF] text-black' : 'text-gray-400'}`}
            >
                <div className={`flex-shrink-0 ${active ? 'text-black' : 'text-current'}`}>
                    {icon}
                </div>
                <div>
                    <span className="block">{title}</span>
                    <span className={`text-[10px] uppercase font-normal block ${active ? 'opacity-80 text-black/70' : 'opacity-50'}`}>{subtitle}</span>
                </div>
            </button>
        );
    };

    return (
        <aside className="w-64 border-r border-[#30363d] p-6 flex-col justify-between hidden md:flex bg-[#0D1117]/50">
            <div className="space-y-6">
                <nav className="space-y-2">
                    <SidebarButton
                        id="overview"
                        title="DASHBOARD"
                        subtitle="Security Overview"
                        icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg>}
                    />
                    <SidebarButton
                        id="sentinel"
                        title="FILE SECURITY"
                        subtitle="Malware, CDR, Metadata"
                        icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>}
                    />
                    <SidebarButton
                        id="guardian"
                        title="DATA & PRIVACY"
                        subtitle="DLP, Compliance, Media"
                        icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>}
                    />
                    <SidebarButton
                        id="security"
                        title="CODE SECURITY"
                        subtitle="Supply Chain & Secrets"
                        icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>}
                    />
                    <SidebarButton
                        id="offline"
                        title="OFFLINE SCANS"
                        subtitle="Large File Jobs Queue"
                        icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"></path></svg>}
                    />

                    {/* Admin-only items */}
                    {user?.role?.toLowerCase() === 'admin' && (
                        <>
                            <a
                                href="/admin/firewall"
                                className="w-full text-left p-3 rounded hover:bg-gray-800 text-sm font-bold transition flex items-center gap-3 text-gray-400 hover:text-white"
                            >
                                <div className="flex-shrink-0">
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                                </div>
                                <div>
                                    <span className="block">AI FIREWALL</span>
                                    <span className="text-[10px] uppercase font-normal block opacity-50">LLM Guard & Audit</span>
                                </div>
                            </a>
                            <a
                                href="/admin/users"
                                className="w-full text-left p-3 rounded hover:bg-gray-800 text-sm font-bold transition flex items-center gap-3 text-gray-400 hover:text-white"
                            >
                                <div className="flex-shrink-0">
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
                                </div>
                                <div>
                                    <span className="block">User Management</span>
                                    <span className="text-[10px] uppercase font-normal block opacity-50">Admin Console</span>
                                </div>
                            </a>
                        </>
                    )}
                </nav>
            </div>

            <div className="mt-auto space-y-4">
                {/* Utility Links */}
                <div className="space-y-1 border-t border-white/5 pt-4">
                    <a href="/api/docs" target="_blank" rel="noopener noreferrer" className="w-full text-left block p-2 rounded hover:bg-gray-800 text-gray-400 text-xs flex items-center gap-2 transition">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
                        API Documentation
                    </a>
                    <a href="/icap" target="_blank" rel="noopener noreferrer" className="w-full text-left block p-2 rounded hover:bg-gray-800 text-gray-400 text-xs flex items-center gap-2 transition">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" /></svg>
                        ICAP Integration
                    </a>
                </div>

                {/* Credits */}
                <div className="glass-panel p-4 rounded-lg opacity-50 pointer-events-none border border-[#30363d] bg-[#161B22]/70">
                    <div className="flex justify-between text-[10px] uppercase font-bold text-gray-500 mb-2">
                        <span>Hourly Credits</span>
                        <span>{credits}/500</span>
                    </div>
                    <div className="w-full h-1.5 bg-gray-800 rounded-full overflow-hidden">
                        <div className="h-full bg-[#88FFFF]" style={{ width: `${Math.min((credits / 500) * 100, 100)}%` }}></div>
                    </div>
                    <p className="text-[9px] text-gray-600 mt-2 italic text-center">Resets in 60 mins</p>
                </div>

                <button onClick={onLogout} className="w-full flex items-center gap-3 p-3 text-sm text-gray-500 hover:text-red-400 hover:bg-gray-800/50 rounded transition">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
                    <span className="font-bold">LOGOUT</span>
                </button>
            </div>
        </aside>
    );
};

export default Sidebar;
