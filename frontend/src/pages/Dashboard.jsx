import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getDashboardData } from '../services/api';
import MainLayout from '../components/layout/MainLayout';
import SentinelTrack from '../components/dashboard/tracks/SentinelTrack';

import GuardianTrack from '../components/dashboard/tracks/GuardianTrack';
import SecurityTrack from '../components/dashboard/tracks/SecurityTrack';

import OverviewTrack from '../components/dashboard/tracks/OverviewTrack';

const Dashboard = () => {
    const navigate = useNavigate();
    const [activeTrack, setActiveTrack] = useState('overview');
    const [credits, setCredits] = useState(0);
    const [user, setUser] = useState({ username: 'Loading...', role: 'user' });

    useEffect(() => {
        // Fetch initial data
        const fetchData = async () => {
            try {
                // Fetch current user info
                const response = await fetch('/api/users/me', {
                    headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token')}` },
                    credentials: 'include'
                });

                if (response.ok) {
                    const userData = await response.json();
                    setUser(userData);
                    setCredits(userData.credits_remaining || 0); // Use actual credits
                } else {
                    // If not authenticated, redirect to login
                    navigate('/login');
                }
            } catch (e) {
                console.error(e);
                navigate('/login');
            }
        };
        fetchData();
    }, [navigate]);

    const handleLogout = () => {
        // Clear session/token
        localStorage.removeItem('token');
        navigate('/login');
    };

    const renderTrack = () => {
        switch (activeTrack) {
            case 'overview': return <OverviewTrack />;
            case 'sentinel': return <SentinelTrack />;
            case 'guardian': return <GuardianTrack />;
            case 'security': return <SecurityTrack />;
            default: return <OverviewTrack />;
        }
    };

    return (
        <MainLayout
            activeTrack={activeTrack}
            setActiveTrack={setActiveTrack}
            user={user}
            onLogout={handleLogout}
            credits={credits}
        >
            {renderTrack()}
        </MainLayout>
    );
};

export default Dashboard;
