import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const HomeHero = () => {
    const navigate = useNavigate();

    // No local particle init needed - handled globally or by LandingLayout

    return (
        <header className="relative pt-32 pb-20 px-4 w-full flex justify-center">
            <div className="w-full max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-16 items-center relative z-10">
                {/* Left Side: Copy */}
                <div className="text-left space-y-8">
                    <div className="inline-block px-3 py-1 rounded-full text-[10px] font-mono border border-[#88FFFF]/30 bg-[#88FFFF]/10 text-[#88FFFF] mb-4 animate-pulse">
                        SCALING SECURITY WITH AI
                    </div>
                    <h1 className="text-5xl md:text-6xl font-black tracking-tighter text-white leading-tight">
                        The Unified <br />
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#88FFFF] to-[#00E5FF]">Immune System</span> <br />
                        for Your Data.
                    </h1>
                    <p className="text-lg text-gray-400 max-w-xl leading-relaxed">
                        One engine to secure your Files, Source Code, and Network Traffic. Block malware, redact PII, and
                        secure your supply chain via API or ICAP.
                    </p>
                    <div className="flex flex-col sm:flex-row gap-4">
                        <button
                            onClick={() => navigate('/register')}
                            className="bg-[#88FFFF] hover:bg-opacity-90 text-black px-8 py-4 rounded-xl font-bold text-lg transition shadow-[0_0_20px_rgba(136,255,255,0.2)] text-center"
                        >
                            Start Scan
                        </button>
                        <a
                            href="/api/docs"
                            className="px-8 py-4 border border-[#88FFFF] text-[#88FFFF] hover:bg-[#88FFFF]/10 rounded-xl font-bold text-lg transition text-center"
                        >
                            Integration Docs
                        </a>
                    </div>
                </div>

                {/* Right Side: Terminal */}
                <div className="relative group">
                    {/* Glow effect */}
                    <div className="absolute -inset-1 bg-gradient-to-r from-[#88FFFF] to-purple-600 rounded-lg blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>

                    <div className="bg-[#0D1117] border border-[#30363d] rounded-xl shadow-2xl font-mono text-sm leading-relaxed overflow-hidden h-80 relative">
                        <div className="bg-[#161B22] p-3 flex gap-2 border-b border-[#30363d]">
                            <div className="w-3 h-3 rounded-full bg-[#FF5F56]"></div>
                            <div className="w-3 h-3 rounded-full bg-[#FFBD2E]"></div>
                            <div className="w-3 h-3 rounded-full bg-[#27C93F]"></div>
                            <div className="ml-4 text-xs text-gray-500">spidercob-engine — zsh — 80x24</div>
                        </div>
                        <div className="p-5 text-[#C9D1D9] text-sm leading-relaxed" id="heroTerminalContent">
                            <div className="mb-2"><span className="text-[#27C93F]">➜</span> <span className="text-[#88FFFF]">~</span> spidercob scan --target /var/www --deep</div>
                            <div className="mb-2 text-gray-500">Initializing engine v2.4.0...</div>
                            <div className="mb-2">[+] Loaded 45,000+ signatures</div>
                            <div className="mb-2">[+] AI Heuristics: <span className="text-[#27C93F]">ONLINE</span></div>
                            <div className="mb-2">Scanning...</div>
                            <div className="mb-2 text-[#F85149]">[!] ALERT: Found potential malware in /uploads/invoice.pdf</div>
                            <div className="mb-2 text-[#F85149]">[!] ALERT: AWS Key detected in src/config.js</div>
                            <div className="mt-4"><span className="text-[#27C93F]">➜</span> <span className="text-[#88FFFF]">~</span> <span className="animate-pulse">_</span></div>
                        </div>
                    </div>
                </div>
            </div>
        </header>
    );
};

export default HomeHero;
