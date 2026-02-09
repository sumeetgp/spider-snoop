import React from 'react';

const MobileMenu = ({ isOpen, onClose, activeTrack, setActiveTrack, onLogout, credits }) => {
    if (!isOpen) return null;

    const MobileTrackButton = ({ id, icon, title, subtitle }) => (
        <button
            onClick={() => {
                if (setActiveTrack) setActiveTrack(id);
                onClose();
            }}
            className={`w-full p-4 rounded-xl text-left flex items-center gap-4 transition ${activeTrack === id ? 'bg-[#88FFFF] text-black' : 'bg-gray-800/50 text-white'}`}
        >
            <div className={`p-2 rounded-lg ${activeTrack === id ? 'bg-black/20' : 'bg-gray-700'}`}>
                {icon}
            </div>
            <div>
                <span className="block text-lg uppercase font-bold">{title}</span>
                <span className={`text-xs ${activeTrack === id ? 'text-black/70' : 'text-gray-400'}`}>{subtitle}</span>
            </div>
        </button>
    );

    return (
        <div className="fixed inset-0 z-[60] bg-[#0D1117]/95 backdrop-blur-xl flex flex-col p-6 overflow-y-auto">
            <div className="flex justify-between items-center mb-8">
                <div className="flex items-center gap-1 text-xl font-black tracking-tighter text-white">
                    <span className="text-2xl">🕸️</span><span>Spider<span className="text-[#88FFFF]">Cob</span></span>
                </div>
                <button onClick={onClose} className="text-gray-400 hover:text-white">
                    <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>

            <div className="flex flex-col gap-6 text-xl font-bold text-gray-400">
                <a href="/" className="hover:text-white transition">Home</a>
                <a href="#features" className="hover:text-white transition">Capabilities</a>
                <a href="/enterprise" className="hover:text-white transition">Enterprise</a>
                <a href="/about" className="hover:text-white transition">About Us</a>
                <a href="/api/docs" className="hover:text-white transition">API Docs</a>

                <div className="h-px bg-white/10 my-2"></div>

                {activeTrack ? (
                    <>
                        <div className="space-y-2">
                            <MobileTrackButton
                                id="overview"
                                title="Dashboard"
                                subtitle="Security Overview"
                                icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg>}
                            />
                            <MobileTrackButton
                                id="sentinel"
                                title="File Guard"
                                subtitle="Malware & Virus"
                                icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>}
                            />
                            <MobileTrackButton
                                id="guardian"
                                title="Secret Scanner"
                                subtitle="PII, Keys & Safe Wash"
                                icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>}
                            />
                            <MobileTrackButton
                                id="vision"
                                title="Media Scanner"
                                subtitle="Video & Audio Leaks"
                                icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>}
                            />
                            <MobileTrackButton
                                id="security"
                                title="Code Security"
                                subtitle="Supply Chain"
                                icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>}
                            />
                        </div>

                        <div className="bg-black/40 p-4 rounded-lg border border-white/10 mt-4">
                            <div className="flex justify-between text-[10px] uppercase font-bold text-gray-500 mb-2">
                                <span>Hourly Credits</span>
                                <span>{credits}/500</span>
                            </div>
                            <div className="w-full h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                <div className="h-full bg-[#88FFFF]" style={{ width: `${Math.min((credits / 500) * 100, 100)}%` }}></div>
                            </div>
                        </div>

                        <button onClick={onLogout} className="mt-8 w-full text-center p-3 rounded-lg text-red-400 font-bold hover:bg-white/5 transition flex items-center justify-center gap-2 border border-red-900/30">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
                            LOGOUT
                        </button>
                    </>
                ) : (
                    <div className="space-y-4 pt-4">
                        <a href="/login" className="block text-center text-gray-400 hover:text-white transition font-bold">[ LOGIN ]</a>
                        <a href="/register" className="block text-center bg-[#88FFFF] text-black px-4 py-3 rounded font-bold">REGISTER NOW</a>
                    </div>
                )}
            </div>
        </div>
    );
};

export default MobileMenu;
