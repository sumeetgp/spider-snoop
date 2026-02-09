import React from 'react';
import LandingLayout from '../components/layout/LandingLayout';
import { useAuth } from '../hooks/useAuth';

const Enterprise = () => {
    const { user, logout } = useAuth();

    return (
        <LandingLayout user={user} onLogout={logout}>
            <div className="flex flex-col items-center justify-center py-20 text-center space-y-8">
                <div className="space-y-4">
                    <h1 className="text-5xl font-black tracking-tighter text-white uppercase">
                        Enterprise <span className="text-[#88FFFF]">Tier</span>
                    </h1>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto font-mono">
                        Scale your security infrastructure with dedicated support and advanced features.
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 w-full max-w-6xl mt-12">
                    {/* Free Tier */}
                    <div className="glass-panel p-8 rounded-2xl border border-[#30363d] bg-[#161B22]/50 opacity-70">
                        <h3 className="text-xl font-bold text-gray-400 mb-2">COMMUNITY</h3>
                        <div className="text-3xl font-black text-white mb-6">$0<span className="text-sm font-normal text-gray-500">/mo</span></div>
                        <ul className="space-y-4 text-sm text-left text-gray-400 mb-8 border-t border-gray-700 pt-6">
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> Basic Malware Scan</li>
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> 50 Credits/Hour</li>
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> Community Support</li>
                        </ul>
                        <button className="w-full py-3 rounded-lg border border-gray-600 text-gray-400 font-bold cursor-not-allowed">CURRENT PLAN</button>
                    </div>

                    {/* Pro Tier */}
                    <div className="glass-panel p-8 rounded-2xl border-2 border-[#88FFFF] bg-[#161B22] relative transform scale-105 shadow-[0_0_30px_rgba(136,255,255,0.1)]">
                        <div className="absolute top-0 right-0 bg-[#88FFFF] text-black text-xs font-bold px-3 py-1 rounded-bl-lg">RECOMMENDED</div>
                        <h3 className="text-xl font-bold text-[#88FFFF] mb-2">PRO OPERATOR</h3>
                        <div className="text-3xl font-black text-white mb-6">$49<span className="text-sm font-normal text-gray-500">/mo</span></div>
                        <ul className="space-y-4 text-sm text-left text-gray-300 mb-8 border-t border-gray-700 pt-6">
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-[#88FFFF]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> Advanced PII Redaction</li>
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-[#88FFFF]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> 5,000 Credits/Hour</li>
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-[#88FFFF]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> Priority Processing</li>
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-[#88FFFF]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> API Access</li>
                        </ul>
                        <button className="w-full py-3 rounded-lg bg-[#88FFFF] hover:bg-white text-black font-bold transition">UPGRADE NOW</button>
                    </div>

                    {/* Enterprise Tier */}
                    <div className="glass-panel p-8 rounded-2xl border border-[#30363d] bg-[#161B22]/50">
                        <h3 className="text-xl font-bold text-white mb-2">AGENCY</h3>
                        <div className="text-3xl font-black text-white mb-6">CUSTOM</div>
                        <ul className="space-y-4 text-sm text-left text-gray-400 mb-8 border-t border-gray-700 pt-6">
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> Unlimited Credits</li>
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> On-Premise Deployment</li>
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> 24/7 Dedicated Support</li>
                            <li className="flex items-center gap-2"><svg className="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg> Custom SLA</li>
                        </ul>
                        <button className="w-full py-3 rounded-lg border border-white text-white hover:bg-white hover:text-black font-bold transition">CONTACT SALES</button>
                    </div>
                </div>
            </div>
        </LandingLayout>
    );
};

export default Enterprise;
