import React from 'react';
import LandingLayout from '../components/layout/LandingLayout';

const FirewallOnboarding = () => {
    return (
        <LandingLayout>
            <div className="max-w-4xl mx-auto w-full p-8 md:p-12">
                <div className="text-center mb-16">
                    <h1 className="text-5xl font-black mb-4 text-transparent bg-clip-text bg-gradient-to-r from-[#88FFFF] to-[#00E5FF]">
                        SECURE YOUR LLM TRAFFIC
                    </h1>
                    <p className="text-xl text-gray-400 max-w-2xl mx-auto">
                        Integrate SpiderCob's **AI Firewall** in 2 minutes. Protect against PII leaks, block unauthorized models, and audit every prompt.
                    </p>
                </div>

                <div className="space-y-12">
                    {/* Step 1 */}
                    <div className="flex gap-6">
                        <div className="flex-shrink-0">
                            <div className="w-8 h-8 bg-[#88FFFF] text-black rounded-full flex items-center justify-center font-bold">1</div>
                        </div>
                        <div className="flex-1">
                            <h3 className="text-2xl font-bold text-white mb-2">Change Base URL</h3>
                            <p className="text-gray-400 mb-4">Replace standard OpenAI endpoints with our secure proxy.</p>
                            <div className="bg-[#161B22] border border-[#30363d] rounded-lg p-4 font-mono text-sm text-green-400 overflow-x-auto">
                                <pre>{`from openai import OpenAI

client = OpenAI(
    api_key="your_spidercob_api_token",
    base_url="https://api.spidercob.com/v1/proxy"
)

completion = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello world!"}]
)`}</pre>
                            </div>
                        </div>
                    </div>

                    {/* Step 2 */}
                    <div className="flex gap-6">
                        <div className="flex-shrink-0">
                            <div className="w-8 h-8 bg-[#88FFFF] text-black rounded-full flex items-center justify-center font-bold">2</div>
                        </div>
                        <div className="flex-1">
                            <h3 className="text-2xl font-bold text-white mb-2">Verify Protection</h3>
                            <p className="text-gray-400 mb-4">Try sending a test prompt containing sensitive data.</p>
                            <div className="bg-[#161B22] border border-[#30363d] rounded-lg p-4 font-mono text-sm text-yellow-400 overflow-x-auto">
                                <pre>{`curl https://api.spidercob.com/v1/proxy/chat/completions \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [
      {"role": "user", "content": "My secret password is..."}
    ]
  }'`}</pre>
                            </div>
                        </div>
                    </div>

                    <div className="text-center pt-10">
                        <a href="/dashboard" className="inline-flex items-center gap-2 bg-[#88FFFF] hover:bg-[#00E5FF] text-black font-bold px-6 py-3 rounded-lg transition">
                            GO TO DASHBOARD
                        </a>
                    </div>
                </div>
            </div>
        </LandingLayout>
    );
};

export default FirewallOnboarding;
