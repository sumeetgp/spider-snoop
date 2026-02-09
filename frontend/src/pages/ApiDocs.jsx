import React from 'react';
import MainLayout from '../components/layout/MainLayout';

const ApiDocs = () => {
    // We can use an iframe to load the existing HTML content for now if it's complex 
    // or rewrite it. The HTML template uses an iframe to `/api/docs/content` anyway!
    // `api_docs.html`: <iframe src="/api/docs/content" ...></iframe>
    // `icap_docs.html` is a full page content.

    // Let's implement a tabbed view or just two sections if we want to combine them as per plan.
    // However, sticking to the existing structure might be safer.
    // The prompt asked to "Port api_docs.html / icap_docs.html to ApiDocs.jsx".
    // I'll create a component that renders the API Docs iframe, and maybe a separate route for ICAP?
    // Or I can put them together.

    // Let's create a simple tabbed interface in this page to show both.

    const [activeTab, setActiveTab] = React.useState('api');

    return (
        <MainLayout>
            <div className="flex gap-4 mb-4 border-b border-gray-700 pb-2">
                <button
                    className={`px-4 py-2 text-sm font-bold rounded ${activeTab === 'api' ? 'bg-[#88FFFF] text-black' : 'text-gray-400 hover:text-white'}`}
                    onClick={() => setActiveTab('api')}
                >
                    API DOCUMENTATION
                </button>
                <button
                    className={`px-4 py-2 text-sm font-bold rounded ${activeTab === 'icap' ? 'bg-[#88FFFF] text-black' : 'text-gray-400 hover:text-white'}`}
                    onClick={() => setActiveTab('icap')}
                >
                    ICAP INTEGRATION
                </button>
            </div>

            {activeTab === 'api' ? (
                <div className="w-full bg-[#0d1117] rounded-xl overflow-hidden border border-[#30363d]" style={{ height: 'calc(100vh - 250px)' }}>
                    <iframe
                        src="/api/docs/content"
                        className="w-full h-full border-none"
                        title="API Documentation"
                        sandbox="allow-same-origin allow-scripts allow-forms"
                    />
                </div>
            ) : (
                <div className="space-y-8 animate-fade-in">
                    <header>
                        <h1 className="text-3xl font-black text-white mb-2">ICAP Integration</h1>
                        <p className="text-lg text-gray-400">Internet Content Adaptation Protocol (RFC 3507) configuration.</p>
                    </header>

                    {/* Connectivity Test */}
                    <div className="glass-panel p-6 rounded-2xl border-l-4 border-[#88FFFF]">
                        <h2 className="text-xl font-bold text-white mb-1">Server Status</h2>
                        <p className="text-sm text-gray-400 mb-4">Verify SpiderCob ICAP server reachability.</p>
                        <div className="flex gap-4">
                            <button className="bg-gray-800 hover:bg-white/10 text-white px-4 py-2 rounded text-sm font-bold border border-gray-700">
                                TEST CONNECTIVITY
                            </button>
                        </div>
                    </div>

                    {/* Squid Config */}
                    <div className="glass-panel p-6 rounded-xl">
                        <h3 className="text-lg font-bold text-white mb-2">Squid Proxy</h3>
                        <div className="bg-[#0d1117] p-4 rounded border border-[#30363d] font-mono text-xs text-blue-300 overflow-x-auto">
                            <pre>{`icap_enable on
icap_service service_req reqmod_precache bypass=0 icaps://icap.spidercob.com:443/reqmod
icap_service service_resp respmod_precache bypass=0 icaps://icap.spidercob.com:443/respmod
request_header_add X-ICAP-Auth "Bearer <your_token>" all`}</pre>
                        </div>
                    </div>
                </div>
            )}
        </MainLayout>
    );
};

export default ApiDocs;
