import React from 'react';

const HomeProblem = () => {
    return (
        <section className="bg-[#161B22]/50 py-24 px-4 border-y border-[#30363d]">
            <div className="max-w-6xl mx-auto text-center">
                <h2 className="text-3xl md:text-5xl font-black text-white mb-4">You Are One "Oops" Away From Disaster.</h2>
                <p className="text-gray-500 mb-16 max-w-2xl mx-auto font-mono text-sm">Modern security isn't just about viruses. It's about data.</p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                    {/* Malware */}
                    <div className="glass-panel bg-[#161B22] p-8 rounded-2xl text-left border-l-4 border-[#F85149]/30 backdrop-blur-md border border-[#30363d]">
                        <div className="text-[#F85149] mb-6">
                            <svg className="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                        </div>
                        <h3 className="text-xl font-bold text-white mb-4">The Hidden Threat</h3>
                        <p className="text-xs text-gray-500 mb-4 font-mono uppercase tracking-widest">Ransomware & Zero-Day</p>
                        <p className="text-gray-400 text-sm leading-relaxed">
                            A vendor sends an invoice that silently executes ransomware when opened. Traditional AV misses it. We don't.
                        </p>
                    </div>

                    {/* PII */}
                    <div className="glass-panel bg-[#161B22] p-8 rounded-2xl text-left border-l-4 border-[#FFBD2E]/30 backdrop-blur-md border border-[#30363d]">
                        <div className="text-[#FFBD2E] mb-6">
                            <svg className="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        </div>
                        <h3 className="text-xl font-bold text-white mb-4">The Accidental Leak</h3>
                        <p className="text-xs text-gray-500 mb-4 font-mono uppercase tracking-widest">PII & Compliance</p>
                        <p className="text-gray-400 text-sm leading-relaxed">
                            An employee uploads a spreadsheet with customer SSNs to a public folder. Now you have a GDPR fine.
                        </p>
                    </div>

                    {/* Dev Error */}
                    <div className="glass-panel bg-[#161B22] p-8 rounded-2xl text-left border-l-4 border-[#88FFFF]/30 backdrop-blur-md border border-[#30363d]">
                        <div className="text-[#88FFFF] mb-6">
                            <svg className="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
                        </div>
                        <h3 className="text-xl font-bold text-white mb-4">The Dev Error</h3>
                        <p className="text-xs text-gray-500 mb-4 font-mono uppercase tracking-widest">Secrets & Supply Chain</p>
                        <p className="text-gray-400 text-sm leading-relaxed">
                            A junior dev commits an AWS Secret Key or a vulnerable library (npm). Hackers are in your cloud within minutes.
                        </p>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default HomeProblem;
