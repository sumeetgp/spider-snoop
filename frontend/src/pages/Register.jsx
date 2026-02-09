import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { login, register } from '../services/api';
import ParticlesBackground from '../components/layout/ParticlesBackground';

// Reusing style from Login.jsx but adding fields
const Register = () => {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: '',
        fullName: ''
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    // Particles handled by LandingLayout

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        if (formData.password !== formData.confirmPassword) {
            setError("Passwords do not match");
            setLoading(false);
            return;
        }

        try {
            // Call API register endpoint
            const data = await register({
                username: formData.username,
                email: formData.email,
                password: formData.password,
                full_name: formData.fullName
            });

            // Auto-login or redirect
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
                {/* Header */}
                <div className="text-center mb-6">
                    <div className="flex items-center justify-center gap-1 text-2xl font-black tracking-tighter text-white">
                        <span className="text-3xl">🕸️</span>
                        <span>Spider<span className="text-[#88FFFF]">Cob</span></span>
                    </div>
                    <h1 className="text-sm font-bold tracking-widest text-gray-400 mt-2">INITIALIZE_IDENTITY</h1>
                    <p className="text-xs font-mono text-gray-600">// CREATE_NEW_RECORD</p>
                </div>

                {error && (
                    <div className="mb-6 p-3 bg-red-900/30 border border-red-500/50 rounded text-red-200 text-xs font-mono text-center">
                        ERROR: {error}
                    </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-3">
                    <div className="space-y-1">
                        <label className="block text-xs font-bold text-[#88FFFF] mb-1">USERNAME</label>
                        <input
                            type="text"
                            name="username"
                            value={formData.username}
                            onChange={handleChange}
                            className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none transition"
                            placeholder="user_handle"
                            required
                        />
                    </div>

                    <div className="space-y-1">
                        <label className="block text-xs font-bold text-[#88FFFF] mb-1">EMAIL</label>
                        <input
                            type="email"
                            name="email"
                            value={formData.email}
                            onChange={handleChange}
                            className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none transition"
                            placeholder="user@domain.com"
                            required
                        />
                    </div>

                    <div className="space-y-1">
                        <label className="block text-xs font-bold text-[#88FFFF] mb-1">PASSWORD</label>
                        <input
                            type="password"
                            name="password"
                            value={formData.password}
                            onChange={handleChange}
                            className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none transition"
                            placeholder="********"
                            required
                        />
                    </div>

                    <div className="space-y-1">
                        <label className="block text-xs font-bold text-[#88FFFF] mb-1">CONFIRM PASSWORD</label>
                        <input
                            type="password"
                            name="confirmPassword"
                            value={formData.confirmPassword}
                            onChange={handleChange}
                            className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none transition"
                            placeholder="********"
                            required
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className={`w-full bg-transparent border border-[#88FFFF] text-[#88FFFF] hover:bg-[#88FFFF] hover:text-black font-bold py-3 px-4 rounded transition mt-4 ${loading ? 'opacity-50 cursor-wait' : ''}`}
                    >
                        {loading ? 'CREATING_RECORD...' : 'REGISTER_USER'}
                    </button>
                </form>

                <div className="mt-6 text-center">
                    <p className="text-xs text-gray-500">
                        EXISTING_RECORD? <Link to="/login" className="text-[#88FFFF] hover:underline">[AUTHENTICATE]</Link>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Register;
