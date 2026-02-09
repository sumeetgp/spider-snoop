import React, { useState } from 'react';
import TrackHeader from '../TrackHeader';
import InputZone from '../InputZone';
import StagingArea from '../StagingArea';
import ScanResults from '../ScanResults';
import { uploadFile } from '../../../services/api';

const SentinelTrack = () => {
    const [file, setFile] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    const [redact, setRedact] = useState(false);

    const handleFileSelect = (selectedFile) => {
        setFile(selectedFile);
        setResult(null);
        setError(null);
    };

    const handleCancel = () => {
        setFile(null);
        setResult(null);
        setError(null);
        setRedact(false);
    };

    const handleScan = async () => {
        setScanning(true);
        setError(null);
        try {
            // Pass correct param (Safe Wash/CDR) if redact is true
            const data = await uploadFile(file, 'sentinel', { correct: redact });
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
                title="FILE SECURITY"
                description="Malware, CDR, Metadata"
            />

            {error && (
                <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg text-red-400 text-sm font-bold">
                    ERROR: {error}
                </div>
            )}

            {!file && !result && (
                <InputZone
                    onFileSelect={handleFileSelect}
                    title="Start Scanning"
                    subtitle="Drop payload or click to inject"
                />
            )}

            {file && !result && (
                <StagingArea
                    file={file}
                    onCancel={handleCancel}
                    onScan={handleScan}
                    isRedactDocsEnabled={true}
                    onRedactToggle={setRedact}
                    redactLabel="Enable Safe Wash (CDR)"
                />
            )}

            {scanning && (
                <div className="text-center py-20">
                    <div className="inline-block w-12 h-12 border-4 border-t-[#88FFFF] border-r-transparent border-b-[#88FFFF] border-l-transparent rounded-full animate-spin"></div>
                    <p className="mt-4 text-[#88FFFF] font-mono text-sm animate-pulse">ANALYZING_PAYLOAD...</p>
                </div>
            )}

            {result && (
                <div className="animate-fade-in">
                    <div className="mb-6 flex justify-between items-center">
                        <h3 className="text-xl font-bold text-white">Scan Complete</h3>
                        <button onClick={handleCancel} className="text-sm text-gray-400 hover:text-white underline">New Scan</button>
                    </div>
                    <ScanResults type="sentinel" data={result} />
                </div>
            )}
        </div>
    );
};

export default SentinelTrack;
