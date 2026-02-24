import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Navbar from '../components/layout/Navbar';
import ScanResults from '../components/dashboard/ScanResults';

const OfflineResult = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const [scanData, setScanData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchScanResult = async () => {
            try {
                const token = localStorage.getItem('access_token');
                if (!token) {
                    navigate('/login');
                    return;
                }

                const res = await fetch(`/api/scans/${id}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });

                if (res.ok) {
                    const data = await res.json();
                    setScanData(data);
                } else {
                    setError("Failed to fetch scan results or scan not found.");
                }
            } catch (err) {
                console.error("Error fetching results", err);
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        fetchScanResult();
    }, [id, navigate]);

    return (
        <div className="min-h-screen bg-[#0D1117] text-[#C9D1D9] font-sans selection:bg-[#88FFFF] selection:text-black">
            <Navbar />

            <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
                <div className="mb-8 flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-black text-white tracking-tight">SCAN RESULTS</h1>
                        <p className="text-gray-400 mt-1">Viewing detailed findings for Scan #{id}</p>
                    </div>
                    <button
                        onClick={() => navigate('/dashboard')}
                        className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-[#88FFFF] text-sm font-bold rounded transition"
                    >
                        &larr; BACK TO DASHBOARD
                    </button>
                </div>

                {loading && (
                    <div className="py-20 text-center">
                        <div className="inline-block w-8 h-8 border-4 border-t-[#88FFFF] border-r-transparent border-b-[#88FFFF] border-l-transparent rounded-full animate-spin mb-4"></div>
                        <p className="text-[#88FFFF] font-mono animate-pulse">LOADING_FINDINGS...</p>
                    </div>
                )}

                {error && (
                    <div className="p-6 border border-red-500/50 bg-red-500/10 text-red-400 rounded-xl font-bold">
                        Error: {error}
                    </div>
                )}

                {!loading && !error && scanData && (
                    <div className="bg-[#0D1117] border border-[#30363d] rounded-xl shadow-2xl p-6">
                        <ScanResults
                            type="guardian"
                            data={scanData}
                            onReset={() => navigate('/dashboard')}
                        />
                    </div>
                )}
            </main>
        </div>
    );
};

export default OfflineResult;
