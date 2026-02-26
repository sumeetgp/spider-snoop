import React, { useState } from 'react';
import TrackHeader from '../TrackHeader';
import InputZone from '../InputZone';
import StagingArea from '../StagingArea';
import ScanResults from '../ScanResults';
import { uploadFile } from '../../../services/api';

const SecurityTrack = () => {
    const [file, setFile] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    const handleFileSelect = (selectedFile) => {
        setFile(selectedFile);
        setResult(null);
        setError(null);
    };

    const handleCancel = () => {
        setFile(null);
        setResult(null);
        setError(null);
    };

    const handleScan = async () => {
        setScanning(true);
        setError(null);
        try {
            const data = await uploadFile(file, 'security');
            console.log('Security scan API response:', data);
            setResult(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setScanning(false);
        }
    };

    return (
        <div className="space-y-6">
            <TrackHeader
                title="CODE SECURITY"
                description="Supply Chain & Secrets"
            />

            {error && (
                <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg text-red-400 text-sm font-bold">
                    ERROR: {error}
                </div>
            )}

            {!file && !result && (
                <InputZone
                    onFileSelect={handleFileSelect}
                    title="Secure Code Scan"
                    subtitle="Drop requirements.txt, package.json, or .zip"
                    acceptedTypes=".txt,.json,.zip"
                    supportedText="SUPPORTED: SOURCE CODE (MAX 50MB)"
                />
            )}

            {file && !result && (
                <StagingArea
                    file={file}
                    onCancel={handleCancel}
                    onScan={handleScan}
                />
            )}

            {scanning && (
                <div className="text-center py-20">
                    <div className="inline-block w-12 h-12 border-4 border-t-[#88FFFF] border-r-transparent border-b-[#88FFFF] border-l-transparent rounded-full animate-spin"></div>
                    <p className="mt-4 text-[#88FFFF] font-mono text-sm animate-pulse">AUDITING_DEPENDENCIES...</p>
                </div>
            )}

            {result && (
                <div className="animate-fade-in">
                    <div className="mb-6 flex justify-between items-center">
                        <h3 className="text-xl font-bold text-white">Audit Complete</h3>
                        <button onClick={handleCancel} className="bg-[#88FFFF] hover:bg-[#66DDDD] text-gray-900 px-4 py-2 rounded-lg text-sm font-bold transition flex items-center gap-2 shadow-lg hover:shadow-[#88FFFF]/20">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                            NEW SCAN
                        </button>
                    </div>
                    <ScanResults type="security" data={result} />
                </div>
            )}
        </div>
    );
};

export default SecurityTrack;
