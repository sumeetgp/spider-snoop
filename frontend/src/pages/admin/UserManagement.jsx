import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const UserManagement = () => {
    const navigate = useNavigate();
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [modalMode, setModalMode] = useState('create'); // 'create' or 'edit'
    const [selectedUser, setSelectedUser] = useState(null);
    const [deleteConfirm, setDeleteConfirm] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');

    // Form state
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        full_name: '',
        role: 'user',
        is_active: true
    });

    useEffect(() => {
        fetchUsers();
    }, []);

    const fetchUsers = async () => {
        try {
            const token = localStorage.getItem('access_token');
            const response = await fetch('/api/users/', {
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                setUsers(data);
            } else if (response.status === 403) {
                setError('Access denied. Admin privileges required.');
            } else if (response.status === 401) {
                navigate('/login');
            } else {
                setError('Failed to load users');
            }
        } catch (err) {
            setError('Network error');
        } finally {
            setLoading(false);
        }
    };

    const handleCreate = () => {
        setModalMode('create');
        setFormData({
            username: '',
            email: '',
            password: '',
            full_name: '',
            role: 'user',
            is_active: true
        });
        setShowModal(true);
    };

    const handleEdit = (user) => {
        setModalMode('edit');
        setSelectedUser(user);
        setFormData({
            username: user.username,
            email: user.email,
            password: '',
            full_name: user.full_name || '',
            role: user.role,
            is_active: user.is_active
        });
        setShowModal(true);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        const token = localStorage.getItem('access_token');

        try {
            const url = modalMode === 'create'
                ? '/api/users/'
                : `/api/users/${selectedUser.id}`;

            const method = modalMode === 'create' ? 'POST' : 'PUT';

            const payload = modalMode === 'create'
                ? formData
                : { ...formData, password: formData.password || undefined };

            const response = await fetch(url, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(payload),
                credentials: 'include'
            });

            if (response.ok) {
                setShowModal(false);
                fetchUsers();
            } else {
                const data = await response.json();
                setError(data.detail || 'Operation failed');
            }
        } catch (err) {
            setError('Network error');
        }
    };

    const handleDelete = async (userId) => {
        const token = localStorage.getItem('access_token');

        try {
            const response = await fetch(`/api/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                credentials: 'include'
            });

            if (response.ok) {
                setDeleteConfirm(null);
                fetchUsers();
            } else {
                const data = await response.json();
                setError(data.detail || 'Delete failed');
            }
        } catch (err) {
            setError('Network error');
        }
    };

    const filteredUsers = users.filter(user =>
        user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.email.toLowerCase().includes(searchTerm.toLowerCase())
    );

    if (loading) {
        return (
            <div className="min-h-screen bg-[#0D1117] flex items-center justify-center">
                <div className="text-[#88FFFF] font-mono">LOADING...</div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-[#0D1117] text-[#C9D1D9] p-8">
            {/* Header */}
            <div className="max-w-7xl mx-auto mb-8">
                <div className="flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-black text-white mb-2">USER MANAGEMENT</h1>
                        <p className="text-sm text-gray-400 font-mono">// ADMIN_CONSOLE</p>
                    </div>
                    <button
                        onClick={() => navigate('/dashboard')}
                        className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded border border-[#30363d] transition"
                    >
                        ← BACK TO DASHBOARD
                    </button>
                </div>
            </div>

            {error && (
                <div className="max-w-7xl mx-auto mb-4 p-4 bg-red-900/30 border border-red-500/50 rounded text-red-200 text-sm font-mono">
                    ERROR: {error}
                </div>
            )}

            {/* Controls */}
            <div className="max-w-7xl mx-auto mb-6 flex gap-4">
                <input
                    type="text"
                    placeholder="Search users..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="flex-1 bg-black/30 border border-[#30363d] rounded p-3 text-white font-mono focus:border-[#88FFFF] focus:outline-none"
                />
                <button
                    onClick={handleCreate}
                    className="px-6 py-3 bg-[#88FFFF] text-black font-bold rounded hover:bg-[#66DDDD] transition"
                >
                    + CREATE USER
                </button>
            </div>

            {/* User Table */}
            <div className="max-w-7xl mx-auto glass-panel rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead className="bg-black/30 border-b border-[#30363d]">
                            <tr>
                                <th className="px-6 py-4 text-left text-xs font-bold text-[#88FFFF] uppercase tracking-wider">ID</th>
                                <th className="px-6 py-4 text-left text-xs font-bold text-[#88FFFF] uppercase tracking-wider">Username</th>
                                <th className="px-6 py-4 text-left text-xs font-bold text-[#88FFFF] uppercase tracking-wider">Email</th>
                                <th className="px-6 py-4 text-left text-xs font-bold text-[#88FFFF] uppercase tracking-wider">Role</th>
                                <th className="px-6 py-4 text-left text-xs font-bold text-[#88FFFF] uppercase tracking-wider">Status</th>
                                <th className="px-6 py-4 text-left text-xs font-bold text-[#88FFFF] uppercase tracking-wider">Created</th>
                                <th className="px-6 py-4 text-left text-xs font-bold text-[#88FFFF] uppercase tracking-wider">Last Login</th>
                                <th className="px-6 py-4 text-left text-xs font-bold text-[#88FFFF] uppercase tracking-wider">Credits</th>
                                <th className="px-6 py-4 text-right text-xs font-bold text-[#88FFFF] uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-[#30363d]">
                            {filteredUsers.map(user => (
                                <tr key={user.id} className="hover:bg-white/5 transition">
                                    <td className="px-6 py-4 text-sm font-mono">{user.id}</td>
                                    <td className="px-6 py-4 text-sm font-bold">{user.username}</td>
                                    <td className="px-6 py-4 text-sm text-gray-400">{user.email}</td>
                                    <td className="px-6 py-4">
                                        <span className={`px-2 py-1 text-xs font-bold rounded ${user.role === 'admin' ? 'bg-red-900/30 text-red-300' :
                                            user.role === 'analyst' ? 'bg-blue-900/30 text-blue-300' :
                                                'bg-gray-800 text-gray-300'
                                            }`}>
                                            {user.role.toUpperCase()}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4">
                                        <span className={`px-2 py-1 text-xs font-bold rounded ${user.is_active ? 'bg-green-900/30 text-green-300' : 'bg-gray-800 text-gray-500'
                                            }`}>
                                            {user.is_active ? 'ACTIVE' : 'INACTIVE'}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-sm text-gray-400">
                                        {user.created_at ? new Date(user.created_at).toLocaleString('en-US', {
                                            year: 'numeric',
                                            month: 'short',
                                            day: 'numeric',
                                            hour: '2-digit',
                                            minute: '2-digit'
                                        }) : 'N/A'}
                                    </td>
                                    <td className="px-6 py-4 text-sm text-gray-400">
                                        {user.last_login ? new Date(user.last_login).toLocaleString('en-US', {
                                            year: 'numeric',
                                            month: 'short',
                                            day: 'numeric',
                                            hour: '2-digit',
                                            minute: '2-digit'
                                        }) : 'Never'}
                                    </td>
                                    <td className="px-6 py-4 text-sm font-mono">{user.credits_remaining || 0}</td>
                                    <td className="px-6 py-4 text-right space-x-2">
                                        <button
                                            onClick={() => handleEdit(user)}
                                            className="px-3 py-1 bg-blue-900/30 text-blue-300 hover:bg-blue-900/50 rounded text-xs font-bold transition"
                                        >
                                            EDIT
                                        </button>
                                        <button
                                            onClick={() => setDeleteConfirm(user)}
                                            className="px-3 py-1 bg-red-900/30 text-red-300 hover:bg-red-900/50 rounded text-xs font-bold transition"
                                        >
                                            DELETE
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Create/Edit Modal */}
            {showModal && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-panel rounded-xl w-full max-w-md p-6">
                        <h2 className="text-xl font-bold text-white mb-4">
                            {modalMode === 'create' ? 'CREATE USER' : 'EDIT USER'}
                        </h2>
                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div>
                                <label className="block text-xs font-bold text-[#88FFFF] mb-1">USERNAME</label>
                                <input
                                    type="text"
                                    value={formData.username}
                                    onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                                    className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none"
                                    required
                                    disabled={modalMode === 'edit'}
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-bold text-[#88FFFF] mb-1">EMAIL</label>
                                <input
                                    type="email"
                                    value={formData.email}
                                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                                    className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none"
                                    required
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-bold text-[#88FFFF] mb-1">
                                    PASSWORD {modalMode === 'edit' && '(leave blank to keep current)'}
                                </label>
                                <input
                                    type="password"
                                    value={formData.password}
                                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                                    className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none"
                                    required={modalMode === 'create'}
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-bold text-[#88FFFF] mb-1">FULL NAME</label>
                                <input
                                    type="text"
                                    value={formData.full_name}
                                    onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                                    className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none"
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-bold text-[#88FFFF] mb-1">ROLE</label>
                                <select
                                    value={formData.role}
                                    onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                                    className="w-full bg-black/30 border border-[#30363d] rounded p-2 text-white font-mono focus:border-[#88FFFF] focus:outline-none"
                                >
                                    <option value="user">User</option>
                                    <option value="analyst">Analyst</option>
                                    <option value="admin">Admin</option>
                                </select>
                            </div>
                            {modalMode === 'edit' && (
                                <div className="flex items-center gap-2">
                                    <input
                                        type="checkbox"
                                        checked={formData.is_active}
                                        onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                                        className="w-4 h-4"
                                    />
                                    <label className="text-sm text-gray-400">Active</label>
                                </div>
                            )}
                            <div className="flex gap-2 pt-4">
                                <button
                                    type="submit"
                                    className="flex-1 px-4 py-2 bg-[#88FFFF] text-black font-bold rounded hover:bg-[#66DDDD] transition"
                                >
                                    {modalMode === 'create' ? 'CREATE' : 'UPDATE'}
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setShowModal(false)}
                                    className="flex-1 px-4 py-2 bg-gray-800 text-white font-bold rounded hover:bg-gray-700 transition"
                                >
                                    CANCEL
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Delete Confirmation */}
            {deleteConfirm && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-panel rounded-xl w-full max-w-md p-6">
                        <h2 className="text-xl font-bold text-red-400 mb-4">CONFIRM DELETE</h2>
                        <p className="text-gray-300 mb-6">
                            Are you sure you want to delete user <span className="font-bold text-white">{deleteConfirm.username}</span>?
                            This action cannot be undone.
                        </p>
                        <div className="flex gap-2">
                            <button
                                onClick={() => handleDelete(deleteConfirm.id)}
                                className="flex-1 px-4 py-2 bg-red-900/30 text-red-300 font-bold rounded hover:bg-red-900/50 transition"
                            >
                                DELETE
                            </button>
                            <button
                                onClick={() => setDeleteConfirm(null)}
                                className="flex-1 px-4 py-2 bg-gray-800 text-white font-bold rounded hover:bg-gray-700 transition"
                            >
                                CANCEL
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default UserManagement;
