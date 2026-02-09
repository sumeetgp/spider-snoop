import React from 'react';

const Footer = () => {
    return (
        <footer className="bg-black py-20 px-8 border-t border-[#30363d]">
            <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-12">
                <div className="space-y-4 col-span-1 md:col-span-2">
                    <div className="text-2xl font-black text-white">Spider<span className="text-[#88FFFF]">Cob</span></div>
                    <p className="text-gray-500 text-sm max-w-xs">SpiderCob Inc. — Securing the Digital Web. Protecting enterprise data through intelligent orchestration.</p>
                </div>
                <div className="space-y-4">
                    <h4 className="text-white font-bold uppercase text-[10px] tracking-widest">Product</h4>
                    <ul className="text-gray-500 text-sm space-y-2">
                        <li><a href="#" className="hover:text-[#88FFFF] transition">File Guard</a></li>
                        <li><a href="#" className="hover:text-[#88FFFF] transition">Safe Wash</a></li>
                        <li><a href="#" className="hover:text-[#88FFFF] transition">Secret Scanner</a></li>
                        <li><a href="/about" className="hover:text-[#88FFFF] transition">About Us</a></li>
                    </ul>
                </div>
                <div className="space-y-4">
                    <h4 className="text-white font-bold uppercase text-[10px] tracking-widest">Resources</h4>
                    <ul className="text-gray-500 text-sm space-y-2">
                        <li><a href="/api/docs" className="hover:text-[#88FFFF] transition">Documentation</a></li>
                        <li><a href="#" className="hover:text-[#88FFFF] transition">Status</a></li>
                        <li><a href="#" className="hover:text-[#88FFFF] transition">GitHub</a></li>
                    </ul>
                </div>
            </div>
            <div className="max-w-6xl mx-auto mt-20 pt-8 border-t border-[#30363d]/30 flex justify-between items-center text-[10px] text-gray-700 font-mono">
                <div>&copy; 2025 ALL RIGHTS RESERVED.</div>
                <div>STAY_SECURED_BY_COB</div>
            </div>
        </footer>
    );
};

export default Footer;
