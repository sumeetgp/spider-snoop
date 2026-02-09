import React from 'react';
import LandingLayout from '../components/layout/LandingLayout';
import { useAuth } from '../hooks/useAuth';

const About = () => {
    const { user, logout } = useAuth();

    return (
        <LandingLayout user={user} onLogout={logout}>
            <div className="flex flex-col items-start max-w-3xl mx-auto py-10 space-y-8">
                <div className="border-l-4 border-[#88FFFF] pl-6">
                    <h1 className="text-4xl font-black text-white tracking-tight uppercase">ABOUT SPIDERCOB</h1>
                    <p className="text-[#88FFFF] font-mono mt-2">v1.2 // CLASSIFIED</p>
                </div>

                <div className="space-y-6 text-gray-300 leading-relaxed text-lg">
                    <p>
                        <strong className="text-white">SpiderCob</strong> is an advanced Data Loss Prevention (DLP) and Content Disarm & Reconstruction (CDR) system designed for high-security environments.
                    </p>
                    <p>
                        It acts as a secure gateway, inspecting all traffic (Files, Text, API calls) for malicious payloads, sensitive data (PII), and intellectual property leaks.
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 w-full">
                    <div className="p-6 bg-[#161B22] border border-[#30363d] rounded-xl">
                        <h3 className="text-xl font-bold text-white mb-4">Core Capabilities</h3>
                        <ul className="space-y-2 text-sm text-gray-400 list-disc list-inside">
                            <li>Multi-Engine Malware Analysis (ClamAV)</li>
                            <li>YARA Rule Matching</li>
                            <li>OCR & NLP-based PII Detection</li>
                            <li>Audio/Video Transcription & Scanning</li>
                            <li>ICAP Protocol Integration</li>
                        </ul>
                    </div>
                    <div className="p-6 bg-[#161B22] border border-[#30363d] rounded-xl">
                        <h3 className="text-xl font-bold text-white mb-4">Architecture</h3>
                        <ul className="space-y-2 text-sm text-gray-400 list-disc list-inside">
                            <li>Dockerized Microservices</li>
                            <li>FastAPI Async Backend</li>
                            <li>React (Obsidian Glass UI)</li>
                            <li>Nginx Reverse Proxy</li>
                        </ul>
                    </div>
                </div>
            </div>
        </LandingLayout>
    );
};

export default About;
