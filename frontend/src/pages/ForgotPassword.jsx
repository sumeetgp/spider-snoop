import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import ParticlesBackground from '../components/layout/ParticlesBackground';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState(false);
    const [error, setError] = useState('');
    const [resetUrl, setResetUrl] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const response = await fetch(`/api/auth/forgot-password?email=${encodeURIComponent(email)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include'
            });

            const data = await response.json();

            if (response.ok) {
                setSuccess(true);
                // In development, show the reset URL
                if (data.dev_reset_url) {
                    setResetUrl(data.dev_reset_url);
                }
            } else {
                setError(data.detail || 'Failed to send reset email');
            }
        } catch (err) {
            setError('Network error. Please try again.');
            console.error('Forgot password error:', err);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center font-sans overflow-hidden relative">
            <ParticlesBackground />
            <div className="glass-panel p-8 rounded-xl w-full max-w-md relative z-10 shadow-2xl">
                {/* Header */}
                <div className="text-center mb-6">
                    <div className="flex items-center justify-center gap-1 text-2xl font-black tracking-tighter text-white">
                        <span className="text-3xl">🕸️</span>
                        <span>Spider<span className="text-[#88FFFF]">Cob</span></span>
                    </div>
                    <h1 className="text-sm font-bold tracking-widest text-gray-400 mt-2">PASSWORD_RECOVERY</h1>
                    <p className="text-xs font-mono text-gray-600">// RESET_ACCESS_CREDENTIALS</p>
                </div>

                {success ? (
                    <div className="space-y-4">
                        <div className="p-4 bg-green-900/30 border border-green-500/50 rounded text-green-200 text-sm font-mono text-center">
                            ✓ Reset link sent! Check your email.
                        </div>

                        {resetUrl && (
                            <div className="p-4 bg-blue-900/30 border border-blue-500/50 rounded">
                                <p className="text-xs text-blue-200 font-mono mb-2">DEV MODE - Reset URL:</p>
                                <a href={resetUrl} className="text-xs text-[#88FFFF] hover:underline break-all">
                                    {resetUrl}
                                </a>
                            </div>
                        )}

                        <Link
                            to="/login"
                            className="block w-full bg-transparent border border-[#88FFFF] text-[#88FFFF] hover:bg-[#88FFFF] hover:text-black font-bold py-3 px-4 rounded transition text-center"
                        >
                            RETURN_TO_LOGIN
                        </Link>
                    </div>
                ) : (
                    <>
                        {error && (
                            <div className="mb-6 p-3 bg-red-900/30 border border-red-500/50 rounded text-red-200 text-xs font-mono text-center">
                                ERROR: {error}
                            </div>
                        )}

                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div className="space-y-1">
                                <label className="block text-xs font-bold text-[#88FFFF] mb-1">EMAIL_ADDRESS</label>
                                <input
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none transition"
                                    placeholder="user@domain.com"
                                    required
                                />
                            </div>

                            <button
                                type="submit"
                                disabled={loading}
                                className={`w-full bg-transparent border border-[#88FFFF] text-[#88FFFF] hover:bg-[#88FFFF] hover:text-black font-bold py-3 px-4 rounded transition ${loading ? 'opacity-50 cursor-wait' : ''}`}
                            >
                                {loading ? 'SENDING...' : 'SEND_RESET_LINK'}
                            </button>
                        </form>

                        <div className="mt-6 text-center">
                            <p className="text-xs text-gray-500">
                                REMEMBER_PASSWORD? <Link to="/login" className="text-[#88FFFF] hover:underline">[LOGIN]</Link>
                            </p>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
};

export default ForgotPassword;
