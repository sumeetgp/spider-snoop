import React, { useState, useEffect } from 'react';
import Navbar from './Navbar';
import MobileMenu from './MobileMenu';
import Footer from './Footer';

const LandingLayout = ({ children, user, onLogout }) => {
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

    useEffect(() => {
        // Safe particle initialization
        const initParticles = () => {
            try {
                if (window.particlesJS && document.getElementById('particles-js')) {
                    window.particlesJS("particles-js", {
                        "particles": {
                            "number": { "value": 60 },
                            "color": { "value": "#ffffff" },
                            "opacity": { "value": 0.3 },
                            "size": { "value": 2 },
                            "line_linked": {
                                "enable": true,
                                "distance": 150,
                                "color": "#ffffff",
                                "opacity": 0.1,
                                "width": 1
                            },
                            "move": { "speed": 1 }
                        },
                        "interactivity": {
                            "events": {
                                "onhover": { "enable": true, "mode": "grab" },
                                "onclick": { "enable": true, "mode": "push" }
                            }
                        },
                        "retina_detect": true
                    });
                }
            } catch (error) {
                console.warn("Particles initialization failed:", error);
            }
        };

        if (window.particlesJS) {
            initParticles();
        } else {
            // Check once more after a delay
            const timer = setTimeout(initParticles, 1000);
            return () => clearTimeout(timer);
        }
    }, []);

    return (
        <div className="min-h-screen flex flex-col font-sans bg-[#0D1117] text-[#C9D1D9] relative overflow-x-hidden">
            <div id="particles-js" className="fixed inset-0 w-full h-full pointer-events-none" style={{ zIndex: 0 }}></div>

            <Navbar
                toggleMobileMenu={() => setIsMobileMenuOpen(true)}
                user={user}
                onLogout={onLogout}
            />

            <MobileMenu
                isOpen={isMobileMenuOpen}
                onClose={() => setIsMobileMenuOpen(false)}
                activeTrack={null}
                setActiveTrack={() => { }}
                onLogout={onLogout}
                credits={0}
            />

            <main className="flex-1 w-full relative z-10">
                {children}
            </main>

            <Footer />
        </div>
    );
};

export default LandingLayout;
