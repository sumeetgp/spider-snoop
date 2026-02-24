import React, { useState, useEffect } from 'react';

const PipelineVisualizer = ({ scanId, initialStatus }) => {
    const [status, setStatus] = useState(initialStatus || 'UPLOADED');
    const [progress, setProgress] = useState(0);
    const [pollError, setPollError] = useState(null);

    const STAGES = [
        { id: 'UPLOADED', label: 'Uploaded to Secure Vault', icon: '🔒' },
        { id: 'MALWARE_SCANNING', label: 'Malware Scanning', icon: '🦠' },
        { id: 'EXTRACTING', label: 'Extracting Data', icon: '📄' },
        { id: 'CONTENT_SCANNING', label: 'NLP DLP Engine', icon: '🔍' },
        { id: 'AI_ANALYSIS', label: 'Zero-Shot AI Analysis', icon: '🧠' },
        { id: 'POLICY_EVAL', label: 'Policy Evaluation', icon: '📜' },
        { id: 'COMPLETED', label: 'Report Generated', icon: '✅' },
    ];

    useEffect(() => {
        // Only poll if not finished
        if (status === 'COMPLETED' || status === 'FAILED') {
            return;
        }

        const interval = setInterval(async () => {
            try {
                const token = localStorage.getItem('token');
                if (!token) return;

                const res = await fetch(`/api/scans/${scanId}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });

                if (res.ok) {
                    const data = await res.json();
                    setStatus(data.status);

                    // Simple progress calculation
                    const currentIndex = STAGES.findIndex(s => s.id === data.status);
                    if (currentIndex !== -1) {
                        setProgress((currentIndex / (STAGES.length - 1)) * 100);
                    } else if (data.status === 'COMPLETED') {
                        setProgress(100);
                    } else if (data.status === 'FAILED') {
                        setProgress(100);
                    }
                } else {
                    console.error("Failed to fetch scan status");
                }
            } catch (err) {
                console.error("Poll Error:", err);
            }
        }, 5000); // Poll every 5s

        return () => clearInterval(interval);
    }, [scanId, status]);

    const currentIndex = STAGES.findIndex(s => s.id === status);

    // Fallbacks if status is unknown/legacy
    const displayIndex = currentIndex === -1 && status === 'COMPLETED' ? STAGES.length - 1 : currentIndex;

    return (
        <div className="p-6 bg-gray-900 border border-gray-700 rounded-lg w-full max-w-3xl mx-auto shadow-2xl">
            <h3 className="text-[#88FFFF] font-mono text-lg mb-6 border-b border-gray-700 pb-2">
                ASYNC PIPELINE: <span className="text-white">SCAN_{scanId}</span>
            </h3>

            {status === 'FAILED' ? (
                <div className="text-center py-10 text-red-400 font-bold text-xl border border-red-500/50 bg-red-500/10 rounded">
                    ⚠️ PIPELINE FAILED
                    <p className="text-sm font-normal text-red-300 mt-2">Timeout or Processing Error Occurred.</p>
                </div>
            ) : (
                <div className="relative pt-4 pb-8">
                    {/* Progress Bar Background */}
                    <div className="absolute left-0 top-1/2 -mt-4 w-full h-1 bg-gray-700 z-0 rounded"></div>

                    {/* Active Progress Bar */}
                    <div className="absolute left-0 top-1/2 -mt-4 h-1 bg-blue-500 z-0 rounded transition-all duration-500 ease-in-out" style={{ width: `${Math.max(0, Math.min(100, progress))}%` }}></div>

                    <div className="flex justify-between relative z-10 w-full">
                        {STAGES.map((stage, idx) => {
                            const isCompleted = idx < displayIndex || status === 'COMPLETED';
                            const isActive = idx === displayIndex && status !== 'COMPLETED';

                            let nodeClasses = "w-10 h-10 rounded-full flex items-center justify-center border-2 text-sm transition-all duration-300 ";
                            if (isCompleted) {
                                nodeClasses += "bg-blue-600 border-blue-400 text-white shadow-[0_0_10px_rgba(59,130,246,0.5)]";
                            } else if (isActive) {
                                nodeClasses += "bg-gray-800 border-[#88FFFF] text-[#88FFFF] shadow-[0_0_15px_rgba(136,255,255,0.6)] animate-pulse";
                            } else {
                                nodeClasses += "bg-gray-800 border-gray-600 text-gray-500";
                            }

                            return (
                                <div key={stage.id} className="flex flex-col items-center group relative w-1/7">
                                    <div className={nodeClasses}>
                                        {stage.icon}
                                    </div>
                                    <div className={`mt-3 text-[10px] md:text-xs font-mono text-center absolute top-12 w-24 ${isActive ? 'text-[#88FFFF]' : 'text-gray-400'}`}>
                                        {stage.label}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {status === 'COMPLETED' && (
                <div className="mt-12 text-center pb-4">
                    <button
                        onClick={() => window.location.href = `/results/${scanId}`}
                        className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded shadow-[0_0_15px_rgba(37,99,235,0.4)] transition-colors"
                    >
                        View Results
                    </button>
                    <button
                        onClick={() => window.location.href = '/dashboard'}
                        className="px-6 py-2 ml-4 bg-gray-600 hover:bg-gray-500 text-white font-bold rounded shadow-[0_0_15px_rgba(75,85,99,0.4)] transition-colors"
                    >
                        Back to Dashboard
                    </button>
                </div>
            )}
        </div>
    );
};

export default PipelineVisualizer;
