const API_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:8000' : '');

export const getHealth = async () => {
    const response = await fetch(`${API_URL}/health`, { credentials: 'include' });
    if (!response.ok) throw new Error('Health check failed');
    return response.json();
};

export const login = async (username, password) => {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);

    const response = await fetch(`${API_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData,
        credentials: 'include'
    });

    if (!response.ok) {
        let msg = 'Invalid credentials';
        try {
            const errData = await response.json();
            msg = errData.detail || msg;
        } catch {
            msg = `Server Error (${response.status})`;
        }
        throw new Error(msg);
    }
    return response.json();
};

export const register = async (userData) => {
    const response = await fetch(`${API_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
    });

    if (!response.ok) {
        let msg = 'Registration failed';
        try {
            const errData = await response.json();
            msg = errData.detail || msg;
        } catch {
            msg = `Server Error (${response.status})`;
        }
        throw new Error(msg);
    }
    return response.json();
};

export const getDashboardData = async () => {
    // This assumes we might have a dashboard data endpoint or we construct it from multiple calls
    // For now, let's just return a mock or basic info if the backend doesn't have a specific aggregated endpoint
    // We'll implemented specific fetchers as needed
    return { message: "Dashboard data" };
};

export const uploadFile = async (file, track = 'sentinel', options = {}) => {
    const formData = new FormData();
    formData.append('file', file);

    let endpoint = `${API_URL}/api/scans/upload_file?track=${track}`;

    if (track === 'security') {
        endpoint = `${API_URL}/api/security/scan`;
        // Security endpoint doesn't use 'track' query param in the same way, handled by router logic
    } else if (track === 'vision') {
        endpoint = `${API_URL}/api/scans/upload_video`;
    } else {
        // Sentinel / Guardian
        if (options.correct) {
            endpoint += `&correct=true`;
        }
    }

    const response = await fetch(endpoint, {
        method: 'POST',
        body: formData,
        credentials: 'include' // Important for session cookies
    });

    if (!response.ok) {
        let msg = 'Upload failed';
        try {
            const err = await response.json();
            msg = err.detail || msg;
        } catch { }
        throw new Error(msg);
    }

    return response.json();
};
