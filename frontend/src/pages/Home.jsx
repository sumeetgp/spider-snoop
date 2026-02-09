import React from 'react';
import LandingLayout from '../components/layout/LandingLayout';
import HomeHero from '../components/home/HomeHero';
import HomeArchitecture from '../components/home/HomeArchitecture';
import HomeProblem from '../components/home/HomeProblem';
import HomeFeatures from '../components/home/HomeFeatures';
import HomeIntegration from '../components/home/HomeIntegration';
import HomeVision from '../components/home/HomeVision';
import { useAuth } from '../hooks/useAuth';

const Home = () => {
    const { user, logout } = useAuth();

    return (
        <LandingLayout user={user} onLogout={logout}>
            <HomeHero />
            <HomeArchitecture />
            <HomeProblem />
            <HomeFeatures />
            <HomeIntegration />
            <HomeVision />
        </LandingLayout>
    );
};

export default Home;
