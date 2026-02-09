import React, { useState } from 'react';

const HomeArchitecture = () => {
    const [isAnimating, setIsAnimating] = useState(false);

    const runAnimation = () => {
        setIsAnimating(true);
        setTimeout(() => setIsAnimating(false), 3000);
    };

    return (
        <section className="py-16 bg-[#0D1117] border-y border-white/5 relative z-20">
            <div className="max-w-6xl mx-auto px-4">
                <div className="text-center mb-16">
                    <h2 className="text-3xl font-bold text-white mb-2">Secure Every Entry Point.</h2>
                    <p className="text-gray-500 text-sm">Full coverage across your entire infrastructure.</p>
                </div>

                <div className="flex flex-col md:flex-row justify-center items-center gap-8 relative">
                    {/* Input Columns */}
                    <div className="flex flex-col gap-6 md:w-1/3">
                        {/* Pipe A: The App */}
                        <div className="glass-panel p-6 rounded-xl border border-white/5 flex items-center gap-4 hover:border-[#88FFFF]/30 transition group bg-[#161B22]/50 backdrop-blur-md">
                            <div className="w-12 h-12 bg-gray-800 rounded-lg flex items-center justify-center text-2xl group-hover:scale-110 transition">📄</div>
                            <div className="text-left">
                                <div className="text-white font-bold text-sm">The App</div>
                                <div className="text-xs text-gray-500 font-mono">User Uploads (API)</div>
                            </div>
                            <div className="ml-auto text-gray-600">→</div>
                        </div>
                        {/* Pipe B: The Network */}
                        <div className="glass-panel p-6 rounded-xl border border-white/5 flex items-center gap-4 hover:border-[#88FFFF]/30 transition group bg-[#161B22]/50 backdrop-blur-md">
                            <div className="w-12 h-12 bg-gray-800 rounded-lg flex items-center justify-center text-2xl group-hover:scale-110 transition">📡</div>
                            <div className="text-left">
                                <div className="text-white font-bold text-sm">The Network</div>
                                <div className="text-xs text-gray-500 font-mono">Corp Proxy (ICAP)</div>
                            </div>
                            <div className="ml-auto text-gray-600">→</div>
                        </div>
                        {/* Pipe C: The Code */}
                        <div className="glass-panel p-6 rounded-xl border border-white/5 flex items-center gap-4 hover:border-[#88FFFF]/30 transition group bg-[#161B22]/50 backdrop-blur-md">
                            <div className="w-12 h-12 bg-gray-800 rounded-lg flex items-center justify-center text-2xl group-hover:scale-110 transition">💻</div>
                            <div className="text-left">
                                <div className="text-white font-bold text-sm">The Code</div>
                                <div className="text-xs text-gray-500 font-mono">CI/CD Pipeline</div>
                            </div>
                            <div className="ml-auto text-gray-600">→</div>
                        </div>
                    </div>

                    {/* Connectors Visual (Desktop) */}
                    <div className="hidden md:flex flex-col justify-center items-center w-24 relative">
                        <div className="w-full border-t-2 border-dashed border-gray-700 relative top-0"></div>
                        <button
                            onClick={runAnimation}
                            className={`absolute bg-[#0D1117] text-[#88FFFF] text-2xl hover:scale-125 transition-transform cursor-pointer z-20 outline-none ${isAnimating ? 'animate-spin' : ''}`}
                        >
                            ▶
                        </button>
                    </div>

                    {/* The Brain */}
                    <div className="md:w-1/4 flex flex-col items-center justify-center relative z-10 transition-transform duration-300">
                        <div className={`w-32 h-32 rounded-full bg-black border-2 border-[#88FFFF] shadow-[0_0_50px_rgba(136,255,255,0.2)] flex items-center justify-center relative overflow-hidden ${isAnimating ? 'scale-110 shadow-[0_0_80px_rgba(136,255,255,0.6)]' : ''} transition-all duration-500`}>
                            <div className="absolute inset-0 bg-[#88FFFF]/10 animate-pulse"></div>
                            <span className="text-4xl relative z-10">🧠</span>
                        </div>
                        <div className="mt-4 text-[#88FFFF] font-bold">SpiderCob Brain</div>
                    </div>

                    {/* Connector */}
                    <div className="hidden md:block text-gray-700">
                        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 8l4 4m0 0l-4 4m4-4H3"></path></svg>
                    </div>

                    {/* Output */}
                    <div className={`glass-panel p-8 rounded-2xl border bg-green-500/5 md:w-1/4 text-center transition-all duration-300 ${isAnimating ? 'border-green-500 bg-green-500/20 scale-105' : 'border-green-500/30'}`}>
                        <div className="w-16 h-16 mx-auto bg-green-500/20 rounded-full flex items-center justify-center mb-4">
                            <svg className="w-8 h-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        </div>
                        <div className="text-white font-bold">Sanitized & Compliant</div>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default HomeArchitecture;
