"use client";
import { useState, useEffect } from "react";
import HomePage from "@/components/homePage";
import Login from "@/components/login";
import ThreatIntelligenceDashboard from "@/components/ThreatIntelligenceDashboard";
import AdvancedDomainAnalysis from "@/components/AdvancedDomainAnalysis";
import FileAnalysis from "@/components/FileAnalysis";

export default function Home() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState("");
  const [activeTab, setActiveTab] = useState("dashboard"); // dashboard, analysis, files

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
        {/* Header */}
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          marginBottom: '2rem' 
        }}>
          <div>
            <h1 style={{ fontSize: '2.5rem', fontWeight: '700', color: '#2563eb', marginBottom: '0.5rem' }}>
              🛡️ DNS Guard Pro
            </h1>
            <p style={{ color: '#4b5563', fontSize: '1.1rem' }}>
              Advanced Network Security & Threat Intelligence Platform
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <span style={{ color: '#6b7280', fontSize: '1rem' }}>
              Welcome, <strong>{username}</strong>
            </span>
            <button
              onClick={handleLogout}
              style={{
                padding: '0.75rem 1.5rem',
                backgroundColor: '#ef4444',
                color: 'white',
                borderRadius: '0.5rem',
                fontWeight: '600',
                border: 'none',
                cursor: 'pointer',
                transition: 'background-color 0.2s',
                fontSize: '1rem'
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

        {/* Navigation Tabs */}
        <div style={{ 
          display: 'flex', 
          gap: '0.5rem', 
          marginBottom: '2rem',
          borderBottom: '2px solid #e5e7eb',
          paddingBottom: '1rem'
        }}>
          <button
            onClick={() => setActiveTab("dashboard")}
            style={{
              padding: '1rem 2rem',
              backgroundColor: activeTab === "dashboard" ? '#2563eb' : '#f3f4f6',
              color: activeTab === "dashboard" ? 'white' : '#374151',
              borderRadius: '0.5rem',
              fontWeight: '600',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s',
              fontSize: '1rem'
            }}
          >
            🎯 Threat Intelligence Dashboard
          </button>
          <button
            onClick={() => setActiveTab("analysis")}
            style={{
              padding: '1rem 2rem',
              backgroundColor: activeTab === "analysis" ? '#2563eb' : '#f3f4f6',
              color: activeTab === "analysis" ? 'white' : '#374151',
              borderRadius: '0.5rem',
              fontWeight: '600',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s',
              fontSize: '1rem'
            }}
          >
            🔍 Advanced Domain Analysis
          </button>
          <button
            onClick={() => setActiveTab("files")}
            style={{
              padding: '1rem 2rem',
              backgroundColor: activeTab === "files" ? '#2563eb' : '#f3f4f6',
              color: activeTab === "files" ? 'white' : '#374151',
              borderRadius: '0.5rem',
              fontWeight: '600',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s',
              fontSize: '1rem'
            }}
          >
            📁 Analyze Suspicious Files
          </button>
        </div>

        {/* Content Based on Active Tab */}
        {activeTab === "dashboard" ? (
          <ThreatIntelligenceDashboard />
        ) : activeTab === "analysis" ? (
          <AdvancedDomainAnalysis />
        ) : (
          <FileAnalysis />
        )}
      </div>
      
      {/* Footer */}
      <footer style={{
        backgroundColor: '#1f2937',
        color: 'white',
        padding: '2rem',
        marginTop: '3rem',
        textAlign: 'center'
      }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem'
          }}>
            <div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '0.5rem' }}>
                🛡️ DNS Guard Pro
              </h3>
              <p style={{ color: '#9ca3af', fontSize: '0.875rem' }}>
                Advanced Network Security & Threat Intelligence Platform
              </p>
            </div>
            <div style={{ textAlign: 'right' }}>
              <p style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '0.25rem' }}>
                Developed by
              </p>
              <p style={{ 
                fontSize: '1.25rem', 
                fontWeight: '700', 
                color: '#60a5fa',
                marginBottom: '0.25rem'
              }}>
                Vidit Purohit
              </p>
              <p style={{ color: '#9ca3af', fontSize: '0.875rem' }}>
                Cybersecurity Engineer & Full-Stack Developer
              </p>
            </div>
          </div>
          <div style={{ 
            borderTop: '1px solid #374151', 
            marginTop: '1.5rem', 
            paddingTop: '1.5rem',
            color: '#9ca3af',
            fontSize: '0.875rem'
          }}>
            <p>© 2024 DNS Guard Pro. All rights reserved. | Built with Next.js, Flask, and Advanced Security APIs</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
