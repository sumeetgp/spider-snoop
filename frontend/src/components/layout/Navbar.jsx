import React from 'react';
import { useNavigate, Link } from 'react-router-dom';

const Navbar = ({ toggleMobileMenu, user, onLogout }) => {
    const navigate = useNavigate();

    return (
        <nav className="border-b border-[#30363d] p-4 flex justify-between items-center bg-[#0D1117]/80 backdrop-blur sticky top-0 z-50">
            <div className="flex items-center gap-2 text-2xl font-black tracking-tighter text-white cursor-pointer" onClick={() => navigate('/')}>
                <span className="text-3xl">🕸️</span>
                <span>Spider<span className="text-[#88FFFF]">Cob</span></span>
            </div>

            {/* Navigation Links */}
            <div className="hidden lg:flex gap-8 items-center text-sm font-bold text-gray-400">
                <a href="/#features" className="hover:text-white transition">Capabilities</a>
                <a href="/api/docs" className="hover:text-white transition">API Docs</a>
                <Link to="/icap" className="hover:text-white transition">ICAP Server</Link>
                <Link to="/about" className="hover:text-white transition">About Us</Link>
            </div>

            {/* Right Section */}
            <div className="flex gap-4 items-center">
                {user ? (
                    // Logged in: Show Launch Console + username + avatar
                    <div className="hidden sm:flex gap-4 items-center">
                        <Link to="/dashboard" className="border border-[#88FFFF] text-[#88FFFF] hover:bg-[#88FFFF]/10 shadow-[0_0_15px_rgba(136,255,255,0.3)] px-5 py-2 rounded-lg text-sm font-bold uppercase transition">
                            Dashboard
                        </Link>
                        <span className="text-sm font-bold text-white uppercase hidden md:inline">{user.username || 'USER'}</span>
                        <div className="w-8 h-8 flex items-center justify-center bg-gray-800 rounded-full border border-gray-700 text-[#88FFFF] hover:text-white transition cursor-pointer">
                            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                                <path d="M12 2C8.686 2 6 4.686 6 8v2H4a2 2 0 00-2 2v6a2 2 0 002 2h2v2a2 2 0 002 2h8a2 2 0 002-2v-2h2a2 2 0 002-2v-6a2 2 0 00-2-2h-2V8c0-3.314-2.686-6-6-6zm0 2c2.209 0 4 1.791 4 4v2H8V8c0-2.209 1.791-4 4-4zm-4 8v6h2v-6H8zm4 0v6h-2v-6h2zm4 0v6h-2v-6h2zm-8 8h8v-2h-8v2z" />
                            </svg>
                        </div>
                    </div>
                ) : (
                    // Logged out: Show login/register
                    <div className="hidden sm:flex gap-4 items-center">
                        <Link to="/login" className="text-sm font-bold text-gray-400 hover:text-white transition uppercase">Login</Link>
                        <Link to="/register" className="border border-[#88FFFF] text-[#88FFFF] hover:bg-[#88FFFF]/10 shadow-[0_0_15px_rgba(136,255,255,0.3)] px-5 py-2 rounded-lg text-sm font-bold uppercase transition">Register</Link>
                    </div>
                )}

                {/* Mobile Menu Button */}
                <button onClick={toggleMobileMenu} className="lg:hidden text-white p-2">
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16"></path>
                    </svg>
                </button>
            </div>
        </nav>
    );
};

export default Navbar;
