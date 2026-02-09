import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Home from './pages/Home';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import About from './pages/About';
import Enterprise from './pages/Enterprise';
import ApiDocs from './pages/ApiDocs';
import FirewallOnboarding from './pages/FirewallOnboarding';
import UserManagement from './pages/admin/UserManagement';
import AIFirewall from './pages/admin/AIFirewall';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/about" element={<About />} />
        <Route path="/api/docs" element={<ApiDocs />} />
        <Route path="/firewall/onboarding" element={<FirewallOnboarding />} />
        <Route path="/admin/users" element={<UserManagement />} />
        <Route path="/admin/firewall" element={<AIFirewall />} />
        {/* Redirect unknown routes to Home */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
