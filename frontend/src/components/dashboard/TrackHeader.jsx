import React from 'react';

const TrackHeader = ({ title, description }) => {
    return (
        <div className="flex justify-between items-end border-b border-[#30363d] pb-6">
            <div>
                <h1 className="text-3xl font-black text-white tracking-tight uppercase bg-clip-text text-transparent bg-gradient-to-br from-[#88FFFF] to-[#00E5FF]">
                    {title}
                </h1>
                <p className="text-sm text-gray-400 font-mono mt-1">
                    {description}
                </p>
            </div>
            <div className="hidden md:block text-right">
                <span className="text-xs text-gray-500 uppercase font-bold block">Current Session</span>
                <span className="font-mono text-[#88FFFF] text-xs">ACTIVE</span>
            </div>
        </div>
    );
};

export default TrackHeader;
