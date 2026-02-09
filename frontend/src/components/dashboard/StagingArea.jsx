import React from 'react';
import { File, X, Play, Shield } from 'lucide-react';

const StagingArea = ({ file, onCancel, onScan, onRedactToggle, isRedactDocsEnabled }) => {
    if (!file) return null;

    const fileSize = (file.size / 1024).toFixed(2) + ' KB';

    return (
        <div className="glass-panel rounded-2xl p-6 text-center border-2 border-dashed border-gray-600 bg-[#161B22]/70 backdrop-blur-md animate-fade-in">
            <div className="mb-6 flex flex-col items-center">
                <div className="w-16 h-16 bg-gray-800 rounded-lg flex items-center justify-center mb-4">
                    <File className="w-8 h-8 text-[#88FFFF]" />
                </div>
                <h3 className="text-xl font-bold text-white mb-1">{file.name}</h3>
                <p className="text-sm text-gray-500">{fileSize}</p>
            </div>

            {/* Redaction Option - DISABLED: Not yet supported
            {isRedactDocsEnabled && (
                <div className="mb-6 flex justify-center items-center gap-2">
                    <label className="flex items-center space-x-2 cursor-pointer bg-gray-800/50 p-2 rounded-lg border border-gray-700 hover:border-[#88FFFF]/50 transition select-none">
                        <input
                            type="checkbox"
                            onChange={(e) => onRedactToggle && onRedactToggle(e.target.checked)}
                            className="form-checkbox text-[#88FFFF] rounded focus:ring-[#88FFFF] bg-gray-900 border-gray-600 h-4 w-4 accent-[#88FFFF]"
                        />
                        <span className="text-sm text-gray-300 font-bold flex items-center gap-2">
                            ENABLE SCAN & CORRECT (REDACT)
                        </span>
                    </label>
                </div>
            )}
            */}

            <div className="flex justify-center gap-4">
                <button
                    onClick={onCancel}
                    className="px-6 py-2 rounded-lg border border-gray-600 text-gray-400 hover:text-white hover:border-gray-500 transition font-bold text-sm flex items-center gap-2"
                >
                    <X className="w-4 h-4" /> CANCEL
                </button>
                <button
                    onClick={onScan}
                    className="px-6 py-2 rounded-lg bg-[#88FFFF] hover:bg-[#00E5FF] text-black shadow-lg hover:shadow-[#88FFFF]/20 transition font-bold text-sm flex items-center gap-2"
                >
                    <Play className="w-4 h-4 fill-current" /> START SCAN
                </button>
            </div>
        </div>
    );
};

export default StagingArea;
