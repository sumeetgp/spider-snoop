import React from 'react';

const HomeFeatures = () => {
    return (
        <section id="features" className="py-24 px-4 bg-[#161B22]/30 border-y border-white/5">
            <div className="max-w-7xl mx-auto">
                <h2 className="text-center text-4xl font-black text-white mb-4">Capabilities</h2>
                <p className="text-center text-gray-500 max-w-2xl mx-auto mb-16">
                    Comprehensive defense for the modern stack.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {/* 1. File Guard */}
                    <div className="glass-panel bg-[#161B22]/50 backdrop-blur-md p-8 rounded-2xl hover:border-[#88FFFF]/50 transition group border border-[#30363d]">
                        <div className="text-4xl mb-6 group-hover:scale-110 transition duration-300">🛡️</div>
                        <h3 className="text-xl font-bold text-white mb-2">File Guard & CDR</h3>
                        <p className="text-[#88FFFF] font-bold text-sm mb-4">"Make Files Safe."</p>
                        <p className="text-gray-400 text-sm leading-relaxed">
                            Disarm malware in PDFs/Docs. Reconstruct safe files instantly.
                        </p>
                    </div>

                    {/* 2. Supply Chain */}
                    <div className="glass-panel bg-[#161B22]/50 backdrop-blur-md p-8 rounded-2xl hover:border-[#FFBD2E]/50 transition group border border-[#30363d]">
                        <div className="text-4xl mb-6 group-hover:scale-110 transition duration-300">📦</div>
                        <h3 className="text-xl font-bold text-white mb-2">Supply Chain Security</h3>
                        <p className="text-[#FFBD2E] font-bold text-sm mb-4">"Secure Your Code."</p>
                        <p className="text-gray-400 text-sm leading-relaxed">
                            Scan package.json, pom.xml, and container manifests for CVEs.
                        </p>
                    </div>

                    {/* 3. DLP */}
                    <div className="glass-panel bg-[#161B22]/50 backdrop-blur-md p-8 rounded-2xl hover:border-[#00E5FF]/50 transition group border border-[#30363d]">
                        <div className="text-4xl mb-6 group-hover:scale-110 transition duration-300">👁️</div>
                        <h3 className="text-xl font-bold text-white mb-2">DLP & Privacy</h3>
                        <p className="text-[#00E5FF] font-bold text-sm mb-4">"Stop The Leaks."</p>
                        <p className="text-gray-400 text-sm leading-relaxed">
                            Detect PII, PCI data, and secrets in text, images (OCR), and audio.
                        </p>
                    </div>

                    {/* 4. Network */}
                    <div className="glass-panel bg-[#161B22]/50 backdrop-blur-md p-8 rounded-2xl hover:border-[#27C93F]/50 transition group border border-[#30363d]">
                        <div className="text-4xl mb-6 group-hover:scale-110 transition duration-300">🌐</div>
                        <h3 className="text-xl font-bold text-white mb-2">Network Defense</h3>
                        <p className="text-[#27C93F] font-bold text-sm mb-4">"Filter The Traffic."</p>
                        <p className="text-gray-400 text-sm leading-relaxed">
                            Plug SpiderCob directly into your Proxy (Squid/F5) to scan downloads in real-time.
                        </p>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default HomeFeatures;
