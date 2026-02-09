import React, { useEffect, useState } from 'react';
import { getHealth } from '../services/api';

const HealthCheck = () => {
    const [status, setStatus] = useState(null);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const checkHealth = async () => {
            try {
                const data = await getHealth();
                setStatus(data);
                setError(null);
            } catch (err) {
                setError(err.message);
                setStatus(null);
            } finally {
                setLoading(false);
            }
        };

        checkHealth();
    }, []);

    if (loading) return <div>Loading backend status...</div>;
    if (error) return <div style={{ color: 'red' }}>Error connecting to backend: {error}</div>;

    return (
        <div style={{ padding: '20px', border: '1px solid #ccc', borderRadius: '5px' }}>
            <h2>Backend Status</h2>
            <pre>{JSON.stringify(status, null, 2)}</pre>
        </div>
    );
};

export default HealthCheck;
