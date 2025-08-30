"use client";
import { useState, useEffect } from "react";
import HomePage from "@/components/homePage";
import Login from "@/components/login";
import DeploymentNotice from "@/components/deploymentNotice";

export default function Home() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState("");

  useEffect(() => {
    // Check if user is already logged in
    const savedUser = localStorage.getItem("dnsguard_user");
    if (savedUser) {
      setIsLoggedIn(true);
      setUsername(savedUser);
    }
  }, []);

  const handleLogin = (user: string) => {
    setIsLoggedIn(true);
    setUsername(user);
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setUsername("");
    localStorage.removeItem("dnsguard_user");
  };

  if (!isLoggedIn) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#eff6ff' }}>
      <div style={{ padding: '2rem', maxWidth: '100%' }}>
        {process.env.NODE_ENV === 'production' && <DeploymentNotice />}
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          marginBottom: '1.5rem' 
        }}>
          <div>
            <h1 style={{ fontSize: '1.875rem', fontWeight: '700', color: '#2563eb', marginBottom: '0.5rem' }}>
              🛡️ DNS Guard
            </h1>
            <p style={{ color: '#4b5563' }}>
              Real-time Network Vulnerabilities Checker
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <span style={{ color: '#6b7280', fontSize: '0.875rem' }}>
              Welcome, <strong>{username}</strong>
            </span>
            <button
              onClick={handleLogout}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: '#ef4444',
                color: 'white',
                borderRadius: '0.5rem',
                fontWeight: '500',
                border: 'none',
                cursor: 'pointer',
                transition: 'background-color 0.2s',
                fontSize: '0.875rem'
              }}
              onMouseOver={(e) => {
                const target = e.target as HTMLButtonElement;
                target.style.backgroundColor = '#dc2626';
              }}
              onMouseOut={(e) => {
                const target = e.target as HTMLButtonElement;
                target.style.backgroundColor = '#ef4444';
              }}
            >
              Logout
            </button>
          </div>
        </div>
        <HomePage />
      </div>
    </div>
  );
}
