import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import ParticlesBackground from '../components/layout/ParticlesBackground';

const ResetPassword = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const [token, setToken] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [verifying, setVerifying] = useState(true);
    const [tokenValid, setTokenValid] = useState(false);
    const [userEmail, setUserEmail] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);

    useEffect(() => {
        const tokenParam = searchParams.get('token');
        if (!tokenParam) {
            setError('No reset token provided');
            setVerifying(false);
            return;
        }

        setToken(tokenParam);
        verifyToken(tokenParam);
    }, [searchParams]);

    const verifyToken = async (tokenValue) => {
        try {
            const response = await fetch(`/api/auth/verify-reset-token/${tokenValue}`);
            const data = await response.json();

            if (response.ok && data.valid) {
                setTokenValid(true);
                setUserEmail(data.email);
            } else {
                setError('Invalid or expired reset token');
            }
        } catch (err) {
            setError('Failed to verify token');
        } finally {
            setVerifying(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        if (newPassword !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (newPassword.length < 6) {
            setError('Password must be at least 6 characters');
            return;
        }

        setLoading(true);

        try {
            const response = await fetch(`/api/auth/reset-password?token=${token}&new_password=${encodeURIComponent(newPassword)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (response.ok) {
                setSuccess(true);
                setTimeout(() => navigate('/login'), 2000);
            } else {
                setError(data.detail || 'Failed to reset password');
            }
        } catch (err) {
            setError('Network error. Please try again.');
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
                    <h1 className="text-sm font-bold tracking-widest text-gray-400 mt-2">RESET_PASSWORD</h1>
                    <p className="text-xs font-mono text-gray-600">// UPDATE_CREDENTIALS</p>
                </div>

                {verifying ? (
                    <div className="text-center py-8">
                        <div className="text-[#88FFFF] font-mono text-sm">VERIFYING_TOKEN...</div>
                    </div>
                ) : !tokenValid ? (
                    <div className="space-y-4">
                        <div className="p-4 bg-red-900/30 border border-red-500/50 rounded text-red-200 text-sm font-mono text-center">
                            ✗ {error || 'Invalid reset token'}
                        </div>
                        <Link
                            to="/forgot-password"
                            className="block w-full bg-transparent border border-[#88FFFF] text-[#88FFFF] hover:bg-[#88FFFF] hover:text-black font-bold py-3 px-4 rounded transition text-center"
                        >
                            REQUEST_NEW_LINK
                        </Link>
                    </div>
                ) : success ? (
                    <div className="space-y-4">
                        <div className="p-4 bg-green-900/30 border border-green-500/50 rounded text-green-200 text-sm font-mono text-center">
                            ✓ Password reset successful!
                        </div>
                        <div className="text-center text-xs text-gray-400 font-mono">
                            Redirecting to login...
                        </div>
                    </div>
                ) : (
                    <>
                        <div className="mb-4 p-3 bg-blue-900/30 border border-blue-500/50 rounded text-blue-200 text-xs font-mono text-center">
                            Resetting password for: {userEmail}
                        </div>

                        {error && (
                            <div className="mb-6 p-3 bg-red-900/30 border border-red-500/50 rounded text-red-200 text-xs font-mono text-center">
                                ERROR: {error}
                            </div>
                        )}

                        <form onSubmit={handleSubmit} className="space-y-3">
                            <div className="space-y-1">
                                <label className="block text-xs font-bold text-[#88FFFF] mb-1">NEW_PASSWORD</label>
                                <input
                                    type="password"
                                    value={newPassword}
                                    onChange={(e) => setNewPassword(e.target.value)}
                                    className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none transition"
                                    placeholder="********"
                                    required
                                    minLength={6}
                                />
                            </div>

                            <div className="space-y-1">
                                <label className="block text-xs font-bold text-[#88FFFF] mb-1">CONFIRM_PASSWORD</label>
                                <input
                                    type="password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none transition"
                                    placeholder="********"
                                    required
                                    minLength={6}
                                />
                            </div>

                            <button
                                type="submit"
                                disabled={loading}
                                className={`w-full bg-transparent border border-[#88FFFF] text-[#88FFFF] hover:bg-[#88FFFF] hover:text-black font-bold py-3 px-4 rounded transition mt-4 ${loading ? 'opacity-50 cursor-wait' : ''}`}
                            >
                                {loading ? 'UPDATING...' : 'RESET_PASSWORD'}
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

export default ResetPassword;
