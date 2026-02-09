import React, { useRef } from 'react';

const InputZone = ({ onFileSelect, acceptedTypes = "*", title = "Start Scanning", subtitle = "Drop payload or click to inject", supportedText = "SUPPORTED: EXE, ZIP, PDF (MAX 50MB)" }) => {
    const fileInputRef = useRef(null);

    const handleClick = () => {
        fileInputRef.current.click();
    };

    const handleFileChange = (e) => {
        if (e.target.files && e.target.files[0]) {
            onFileSelect(e.target.files[0]);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            onFileSelect(e.dataTransfer.files[0]);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
    };

    return (
        <div
            onClick={handleClick}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            className="glass-panel rounded-2xl p-10 text-center cursor-pointer hover:border-[#88FFFF] transition border-2 border-dashed border-[#30363d] group bg-[#161B22]/70 backdrop-blur-md"
        >
            <div className="mb-4 text-gray-600 group-hover:text-[#88FFFF] transition">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-12 w-12 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
            </div>

            <h3 className="text-xl font-bold text-white mb-2">{title}</h3>
            <p className="text-sm text-gray-500 mb-6">{subtitle}</p>

            <div className="text-xs font-mono text-gray-600 bg-black/20 inline-block px-3 py-1 rounded">
                {supportedText}
            </div>

            <input
                type="file"
                ref={fileInputRef}
                className="hidden"
                accept={acceptedTypes}
                onChange={handleFileChange}
            />
        </div>
    );
};

export default InputZone;
