import React from 'react';

const HomeVision = () => {
    return (
        <section className="py-32 px-4">
            <div className="max-w-4xl mx-auto glass-panel p-16 rounded-[3rem] bg-gradient-to-br from-cyan-900/20 to-cyan-900/40 text-center border-brand/20 overflow-hidden relative border border-[#88FFFF]/20">
                <div className="absolute inset-0 opacity-10" style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, #88FFFF 1px, transparent 0)', backgroundSize: '40px 40px' }}></div>
                <div className="relative z-10">
                    <span className="text-xs font-mono font-bold tracking-[0.4em] text-[#88FFFF] mb-6 block">COMING SOON</span>
                    <h2 className="text-4xl md:text-5xl font-black text-white mb-8">Autonomous Red Teaming</h2>
                    <p className="text-gray-400 text-lg mb-10 max-w-2xl mx-auto">
                        We are integrating Stanford’s ARTEMIS agent. Soon, you won't just scan files—you'll legally "hack" your own infrastructure to find holes before the bad guys do.
                    </p>
                    <a href="#" className="text-white font-bold border-b-2 border-[#88FFFF] pb-1 hover:text-[#88FFFF] transition">
                        Join the Waitlist for SpiderCob Red Team &rarr;
                    </a>
                </div>
            </div>
        </section>
    );
};

export default HomeVision;
