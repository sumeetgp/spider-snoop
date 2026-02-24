import React, { useEffect, useState } from 'react';
import PipelineVisualizer from './PipelineVisualizer';
import { RefreshCw, Play, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import InputZone from '../InputZone';
import StagingArea from '../StagingArea';
import { uploadFile } from '../../../services/api';

const OfflineTrack = () => {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeScanId, setActiveScanId] = useState(null);
    const [file, setFile] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [error, setError] = useState(null);

    const fetchOfflineScans = async () => {
        setLoading(true);
        try {
            // Fetch latest scans. In reality, you'd filter via API (?source=OFFLINE) 
            // but for now we filter client-side for rapid deployment
            const res = await fetch(`/api/scans/?limit=50`, {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token')}` }
            });
            if (res.ok) {
                const data = await res.json();
                const offlineScans = data.filter(s => s.source && s.source.startsWith('OFFLINE:'));
                setScans(offlineScans);
            }
        } catch (error) {
            console.error("Failed to fetch offline scans", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchOfflineScans();
        // Auto-refresh the list every 15 seconds
        const interval = setInterval(fetchOfflineScans, 15000);
        return () => clearInterval(interval);
    }, []);

    const handleFileSelect = (selectedFile) => {
        setFile(selectedFile);
        setError(null);
    };

    const handleCancel = () => {
        setFile(null);
        setError(null);
    };

    const handleUpload = async () => {
        setUploading(true);
        setError(null);
        try {
            // Default track is 'guardian' for offline
            const data = await uploadFile(file, 'guardian');
            if (data.source && data.source.startsWith("OFFLINE: ")) {
                setActiveScanId(data.id);
                fetchOfflineScans();
            } else {
                alert("File processed instantly synchronously because it was small.");
                fetchOfflineScans();
            }
            setFile(null);
        } catch (err) {
            setError(err.message);
        } finally {
            setUploading(false);
        }
    };

    const getStatusIcon = (status) => {
        if (status === 'COMPLETED') return <CheckCircle className="text-green-400 w-5 h-5" />;
        if (status === 'FAILED') return <XCircle className="text-red-400 w-5 h-5" />;
        if (status === 'UPLOADED') return <AlertTriangle className="text-yellow-400 w-5 h-5" />;
        return <Play className="text-blue-400 w-5 h-5 animate-pulse" />;
    };

    return (
        <div className="space-y-6 animate-fade-in pb-10">
            <div className="flex justify-between items-center border-b border-[#30363d] pb-4">
                <div>
                    <h2 className="text-2xl font-black text-white tracking-tight">OFFLINE QUEUE</h2>
                    <p className="text-gray-400 text-sm">Background tasks processing large files (&gt;10MB).</p>
                </div>
                <button
                    onClick={fetchOfflineScans}
                    className="p-2 bg-gray-800 hover:bg-gray-700 rounded text-[#88FFFF] flex items-center gap-2 transition"
                >
                    <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                    <span className="text-xs font-bold">REFRESH</span>
                </button>
            </div>

            {/* Error State */}
            {error && (
                <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg text-red-400 text-sm font-bold">
                    ERROR: {error}
                </div>
            )}

            {/* Upload Area */}
            <div className="mb-6">
                {!file && (
                    <InputZone
                        onFileSelect={handleFileSelect}
                        title="Upload Large File"
                        subtitle="Upload files over 10MB to queue for background processing"
                        acceptedTypes=".txt,.pdf,.docx,.png,.jpg,.jpeg,.mp4,.mov,.zip,.tar.gz"
                        supportedText="ANY FILE SUPPORTED (>10MB recommended)"
                    />
                )}
                {file && !uploading && (
                    <StagingArea
                        file={file}
                        onCancel={handleCancel}
                        onScan={handleUpload}
                    />
                )}
                {uploading && (
                    <div className="text-center py-10 bg-[#161B22]/50 border border-[#30363d] rounded-xl flex flex-col items-center justify-center">
                        <div className="inline-block w-8 h-8 border-4 border-t-[#88FFFF] border-r-transparent border-b-[#88FFFF] border-l-transparent rounded-full animate-spin"></div>
                        <p className="mt-4 text-[#88FFFF] font-mono text-sm animate-pulse">UPLOADING_&_QUEUING...</p>
                    </div>
                )}
            </div>

            {/* Active Monitor View */}
            {activeScanId && (
                <div className="mb-8 relative border border-gray-700 bg-[#0D1117] p-2 rounded-xl shadow-2xl">
                    <button
                        onClick={() => setActiveScanId(null)}
                        className="absolute top-4 right-4 text-gray-500 hover:text-white font-bold text-xl px-2 z-20"
                    >
                        &times;
                    </button>
                    <PipelineVisualizer scanId={activeScanId} />
                </div>
            )}

            {/* List View */}
            <div className="bg-[#0D1117] border border-[#30363d] rounded-xl overflow-hidden">
                <table className="w-full text-left">
                    <thead>
                        <tr className="bg-[#161B22] text-xs uppercase text-gray-400 font-bold border-b border-[#30363d]">
                            <th className="p-4 w-12"></th>
                            <th className="p-4">Scan ID</th>
                            <th className="p-4">Filename</th>
                            <th className="p-4">Status Stage</th>
                            <th className="p-4">Submitted</th>
                            <th className="p-4">Action</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-[#30363d]">
                        {loading && scans.length === 0 ? (
                            <tr><td colSpan="6" className="p-8 text-center text-gray-500">Loading Queue...</td></tr>
                        ) : scans.length === 0 ? (
                            <tr><td colSpan="6" className="p-8 text-center text-gray-500 italic">No offline scans in queue.</td></tr>
                        ) : scans.map((scan) => {
                            // Clean the filename
                            const filenameMatch = scan.content?.match(/\[ASYNC UPLOAD\] (.*) \(/);
                            let cleanName = filenameMatch ? filenameMatch[1] : scan.source.replace("OFFLINE: ", "").substring(0, 30);
                            if (cleanName.length > 30) cleanName = cleanName.substring(0, 27) + "...";

                            return (
                                <tr key={scan.id} className="hover:bg-white/5 transition text-sm">
                                    <td className="p-4">
                                        {getStatusIcon(scan.status)}
                                    </td>
                                    <td className="p-4 font-mono text-gray-400">#{scan.id}</td>
                                    <td className="p-4 font-bold text-gray-300">{cleanName}</td>
                                    <td className="p-4">
                                        <span className="px-2 py-1 bg-gray-800 border border-gray-700 rounded text-xs text-[#88FFFF]">
                                            {scan.status}
                                        </span>
                                    </td>
                                    <td className="p-4 text-xs text-gray-500">{new Date(scan.created_at).toLocaleString()}</td>
                                    <td className="p-4">
                                        {scan.status === 'COMPLETED' ? (
                                            <button
                                                onClick={() => window.location.href = `/results/${scan.id}`}
                                                className="px-3 py-1 bg-green-600 hover:bg-green-500 text-white rounded font-bold text-xs transition shadow-[0_0_10px_rgba(34,197,94,0.4)]"
                                            >
                                                VIEW RESULTS
                                            </button>
                                        ) : scan.status === 'FAILED' ? (
                                            <span className="text-red-500 font-bold text-xs opacity-50 cursor-not-allowed">ABORTED</span>
                                        ) : (
                                            <button
                                                onClick={() => setActiveScanId(scan.id)}
                                                className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded font-bold text-xs transition"
                                            >
                                                MONITOR
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default OfflineTrack;
