import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { login } from '../services/api';

import ParticlesBackground from '../components/layout/ParticlesBackground';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();


    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const data = await login(username, password);

            // Save the access token to localStorage
            if (data.access_token) {
                localStorage.setItem('access_token', data.access_token);
            }

            navigate('/dashboard');
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center font-sans overflow-hidden relative">
            <ParticlesBackground />
            <div className="glass-panel p-8 rounded-xl w-full max-w-md relative z-10 shadow-2xl">
                <a href="/" className="absolute top-4 right-4 text-gray-500 hover:text-white transition">&times;</a>

                <div className="text-center mb-8">
                    <div className="flex items-center justify-center gap-1 text-2xl font-black tracking-tighter text-white">
                        <span className="text-3xl">🕸️</span><span>Spider<span className="text-brand">Cob</span></span>
                    </div>
                    <h1 className="text-sm font-bold tracking-widest text-gray-400 mt-2">ACCESS CONTROL</h1>
                    <p className="text-xs font-mono text-gray-600">// AUTHENTICATE_USER</p>
                </div>

                <form onSubmit={handleLogin} className="space-y-4">
                    <div>
                        <label className="block text-xs font-bold text-brand mb-1">USERNAME</label>
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            className="w-full bg-black/30 border border-border rounded p-2 text-white font-mono focus:border-brand focus:outline-none transition"
                            required
                            placeholder="enter_username"
                        />
                    </div>
                    <div>
                        <label className="block text-xs font-bold text-brand mb-1">PASSWORD</label>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="w-full bg-black/30 border border-border rounded p-2 text-white font-mono focus:border-brand focus:outline-none transition"
                            required
                            placeholder="enter_password"
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className={`w-full bg-transparent border border-brand text-brand hover:bg-brand hover:text-white font-bold py-3 px-4 rounded transition mt-4 ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
                    >
                        {loading ? 'AUTHENTICATING...' : 'LOGIN'}
                    </button>

                    {error && (
                        <div className="mt-4 p-3 bg-red-900/30 border border-red-500/50 rounded text-red-200 text-xs font-mono text-center">
                            ERROR: {error}
                        </div>
                    )}
                </form>

                <div className="mt-6 text-center">
                    <p className="text-xs text-gray-500">
                        NO_ACCOUNT? <a href="/register" className="text-brand hover:underline">[REGISTER]</a>
                    </p>
                    <p className="text-xs text-gray-500 mt-2">
                        FORGOT_PASSWORD? <a href="/forgot-password" className="text-brand hover:underline">[RESET]</a>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Login;
