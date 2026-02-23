import React, { useState } from 'react';
import TrackHeader from '../TrackHeader';
import InputZone from '../InputZone';
import StagingArea from '../StagingArea';
import ScanResults from '../ScanResults';
import PipelineVisualizer from './PipelineVisualizer';
import { uploadFile } from '../../../services/api';

const GuardianTrack = () => {
    const [file, setFile] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState(null);
    const [asyncScanId, setAsyncScanId] = useState(null);
    const [error, setError] = useState(null);

    const handleFileSelect = (selectedFile) => {
        setFile(selectedFile);
        setResult(null);
        setAsyncScanId(null);
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
            // Smart Routing: Check file type
            const isMedia = file.type.startsWith('video/') || file.type.startsWith('audio/');
            // Also check extension as fallback
            const isMediaExt = /\.(mp4|mov|avi|mkv|mp3|wav|m4a|flac)$/i.test(file.name);

            const track = (isMedia || isMediaExt) ? 'vision' : 'guardian';

            const data = await uploadFile(file, track);

            // Check if Offline Scan was triggered
            if (data.source && data.source.startsWith("OFFLINE: ")) {
                setAsyncScanId(data.id);
            } else {
                setResult(data);
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setScanning(false);
        }
    };

    return (
        <div className="space-y-6">
            <TrackHeader
                title="DATA & PRIVACY"
                description="DLP, Compliance, Media"
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
                    subtitle="Drop documents, images, or media files..."
                    acceptedTypes=".txt,.pdf,.docx,.png,.jpg,.jpeg,.mp4,.mov,.avi,.mkv,.mp3,.wav,.m4a,.flac"
                    supportedText="SUPPORTED: DOCS, IMAGES, VIDEO & AUDIO (MAX 500MB)"
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
                    <p className="mt-4 text-[#88FFFF] font-mono text-sm animate-pulse">ANALYZING_DATA...</p>
                </div>
            )}

            {asyncScanId && !result && !scanning && (
                <div className="py-10">
                    <PipelineVisualizer scanId={asyncScanId} />
                </div>
            )}

            {result && !asyncScanId && (
                <ScanResults type="guardian" data={result} onReset={handleCancel} />
            )}
        </div>
    );
};

export default GuardianTrack;
