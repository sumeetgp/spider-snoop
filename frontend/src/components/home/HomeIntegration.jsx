import React, { useState } from 'react';

const HomeIntegration = () => {
    const [activeTab, setActiveTab] = useState('api');

    return (
        <section className="py-24 px-4 bg-[#0D1117] border-t border-white/5">
            <div className="max-w-5xl mx-auto">
                <div className="text-center mb-12">
                    <h2 className="text-3xl font-bold text-white mb-4">Plug into any layer of your stack.</h2>
                    <p className="text-gray-500">Native integrations for every entry point.</p>
                </div>

                {/* Tabs */}
                <div className="flex justify-center gap-4 mb-8">
                    <button
                        onClick={() => setActiveTab('api')}
                        className={`px-6 py-2 rounded-lg font-mono text-sm font-bold transition ${activeTab === 'api' ? 'bg-[#88FFFF] text-black shadow-[0_0_15px_rgba(136,255,255,0.4)]' : 'bg-gray-800 text-gray-400 hover:text-white'}`}
                    >
                        REST API
                    </button>
                    <button
                        onClick={() => setActiveTab('icap')}
                        className={`px-6 py-2 rounded-lg font-mono text-sm font-bold transition ${activeTab === 'icap' ? 'bg-[#88FFFF] text-black shadow-[0_0_15px_rgba(136,255,255,0.4)]' : 'bg-gray-800 text-gray-400 hover:text-white'}`}
                    >
                        ICAP Proxy
                    </button>
                    <button
                        onClick={() => setActiveTab('cicd')}
                        className={`px-6 py-2 rounded-lg font-mono text-sm font-bold transition ${activeTab === 'cicd' ? 'bg-[#88FFFF] text-black shadow-[0_0_15px_rgba(136,255,255,0.4)]' : 'bg-gray-800 text-gray-400 hover:text-white'}`}
                    >
                        CI/CD
                    </button>
                </div>

                {/* Code Window */}
                <div className="glass-panel rounded-xl overflow-hidden shadow-2xl border border-gray-700">
                    <div className="bg-[#0D1117] p-3 border-b border-gray-700 flex items-center gap-2">
                        <div className="flex gap-2">
                            <div className="w-3 h-3 rounded-full bg-red-500"></div>
                            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                            <div className="w-3 h-3 rounded-full bg-green-500"></div>
                        </div>
                    </div>

                    <div className="p-6 overflow-x-auto bg-[#0D1117]">
                        {activeTab === 'api' && (
                            <pre className="font-mono text-sm text-gray-300">
                                <span className="text-purple-400">import</span> requests{'\n\n'}
                                <span className="text-gray-500"># Scan a file upload</span>{'\n'}
                                resp = requests.post({'\n'}
                                {'    '}<span className="text-green-400">"https://api.spidercob.com/v1/scan"</span>,{'\n'}
                                {'    '}files={`{`}<span className="text-green-400">"file"</span>: open(<span className="text-green-400">"resume.pdf"</span>, <span className="text-green-400">"rb"</span>){`}`},{'\n'}
                                {'    '}data={`{`}<span className="text-green-400">"mode"</span>: <span className="text-green-400">"deep_scan"</span>{`}`}{'\n'}
                                ){'\n\n'}
                                <span className="text-blue-400">print</span>(resp.json())
                            </pre>
                        )}

                        {activeTab === 'icap' && (
                            <pre className="font-mono text-sm text-gray-300">
                                <span className="text-gray-500"># squid.conf - Protect your corporate network</span>{'\n\n'}
                                icap_enable <span className="text-purple-400">on</span>{'\n'}
                                icap_preview_enable <span className="text-purple-400">on</span>{'\n'}
                                icap_preview_size <span className="text-blue-400">1024</span>{'\n\n'}
                                <span className="text-gray-500"># Define SpiderCob Service</span>{'\n'}
                                icap_service <span className="text-[#FFBD2E]">spidercob_req</span> reqmod_precache icap://spidercob-engine:1344/reqmod{'\n'}
                                icap_service <span className="text-[#FFBD2E]">spidercob_resp</span> respmod_precache icap://spidercob-engine:1344/respmod{'\n\n'}
                                <span className="text-gray-500"># Apply to all traffic</span>{'\n'}
                                adaptation_access <span className="text-[#FFBD2E]">spidercob_req</span> allow all{'\n'}
                                adaptation_access <span className="text-[#FFBD2E]">spidercob_resp</span> allow all
                            </pre>
                        )}

                        {activeTab === 'cicd' && (
                            <pre className="font-mono text-sm text-gray-300">
                                <span className="text-gray-500"># .github/workflows/security.yml</span>{'\n'}
                                <span className="text-blue-400">name:</span> SpiderCob Code Scan{'\n\n'}
                                <span className="text-blue-400">on:</span> [push, pull_request]{'\n\n'}
                                <span className="text-blue-400">jobs:</span>{'\n'}
                                {'  '}<span className="text-[#FFBD2E]">security-check:</span>{'\n'}
                                {'    '}<span className="text-blue-400">runs-on:</span> ubuntu-latest{'\n'}
                                {'    '}<span className="text-blue-400">steps:</span>{'\n'}
                                {'      '}- <span className="text-blue-400">uses:</span> actions/checkout@v3{'\n\n'}
                                {'      '}- <span className="text-blue-400">name:</span> Run SpiderCob CLI{'\n'}
                                {'        '}<span className="text-blue-400">run:</span> |{'\n'}
                                {'          '}curl -sL https://spidercob.com/cli | bash{'\n'}
                                {'          '}spidercob-cli scan --target ./src --check-secrets --fail-on-critical{'\n'}
                                {'        '}<span className="text-blue-400">env:</span>{'\n'}
                                {'          '}<span className="text-[#FFBD2E]">SPIDERCOB_API_KEY:</span> ${`{`}{`{`} secrets.SPIDERCOB_KEY {`}`}{`}`}
                            </pre>
                        )}
                    </div>
                </div>
            </div>

            {/* Bottom CTA */}
            <div className="max-w-5xl mx-auto mt-24 text-center">
                <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-16">
                    <a href="/register" className="w-full sm:w-auto bg-[#88FFFF] hover:bg-opacity-90 text-black px-10 py-5 rounded-xl font-black text-lg transition shadow-xl shadow-[#88FFFF]/20 flex items-center justify-center">
                        Start Scanning - Free
                    </a>
                    <a href="/api/docs" className="w-full sm:w-auto border border-[#88FFFF] text-[#88FFFF] hover:bg-[#88FFFF]/10 px-10 py-5 rounded-xl font-black text-lg transition flex items-center justify-center">
                        Read API Docs
                    </a>
                </div>

                {/* Trust Badges */}
                <div className="pt-10 border-t border-[#30363d]/50">
                    <p className="text-[10px] uppercase tracking-[0.2em] text-gray-500 font-bold mb-6">Trusted by developers securing:</p>
                    <div className="flex flex-wrap justify-center gap-6 opacity-40 grayscale hover:opacity-100 transition duration-500">
                        <span className="font-mono font-bold text-xl text-white">Node.js</span>
                        <span className="text-2xl opacity-20 text-white">•</span>
                        <span className="font-mono font-bold text-xl text-white">Python</span>
                        <span className="text-2xl opacity-20 text-white">•</span>
                        <span className="font-mono font-bold text-xl text-white">AWS</span>
                        <span className="text-2xl opacity-20 text-white">•</span>
                        <span className="font-mono font-bold text-xl text-white">Docker</span>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default HomeIntegration;
