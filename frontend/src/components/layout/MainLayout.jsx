import React, { useState } from 'react';
import Navbar from './Navbar';
import Sidebar from './Sidebar';
import MobileMenu from './MobileMenu';
import ParticlesBackground from './ParticlesBackground';

const MainLayout = ({ children, activeTrack, setActiveTrack, user, onLogout, credits = 0 }) => {
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

    return (
        <div className="min-h-screen flex flex-col font-sans bg-[#0D1117] text-[#C9D1D9]">
            <ParticlesBackground />

            <Navbar
                toggleMobileMenu={() => setIsMobileMenuOpen(true)}
                user={user}
                onLogout={onLogout}
            />

            <MobileMenu
                isOpen={isMobileMenuOpen}
                onClose={() => setIsMobileMenuOpen(false)}
                activeTrack={activeTrack}
                setActiveTrack={setActiveTrack}
                onLogout={onLogout}
                credits={credits}
            />

            <div className="flex flex-1 overflow-hidden">
                {activeTrack !== undefined && setActiveTrack ? (
                    <Sidebar
                        activeTrack={activeTrack}
                        setActiveTrack={setActiveTrack}
                        credits={credits}
                        onLogout={onLogout}
                        user={user}
                    />
                ) : null}
                <main className="flex-1 p-4 md:p-8 overflow-y-auto relative scroll-smooth">
                    <div className="max-w-5xl mx-auto space-y-6">
                        {children}
                    </div>
                </main>
            </div>
        </div>
    );
};

export default MainLayout;
