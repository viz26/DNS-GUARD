"use client";
import { useState } from "react";
import toast from "react-hot-toast";

interface LoginProps {
  onLogin: (username: string) => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!username.trim() || !password.trim()) {
      toast.error("Please enter both username and password");
      return;
    }

    setIsLoading(true);
    
    // Simulate login delay
    setTimeout(() => {
      // Basic authentication - in real app, this would be server-side
      if (username === "admin" && password === "admin123") {
        toast.success("Login successful!");
        onLogin(username);
        localStorage.setItem("dnsguard_user", username);
      } else {
        toast.error("Invalid credentials. Use admin/admin123");
      }
      setIsLoading(false);
    }, 1000);
  };

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#eff6ff',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem'
    }}>
      <div style={{
        backgroundColor: 'white',
        borderRadius: '0.75rem',
        padding: '2.5rem',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
        border: '1px solid #e5e7eb',
        maxWidth: '400px',
        width: '100%'
      }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h1 style={{ fontSize: '2rem', fontWeight: '700', color: '#2563eb', marginBottom: '0.5rem' }}>
            🛡️ DNS Guard
          </h1>
          <p style={{ color: '#6b7280' }}>
            Network Security Dashboard
          </p>
        </div>

        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              style={{
                width: '100%',
                padding: '0.75rem',
                borderRadius: '0.5rem',
                border: '1px solid #d1d5db',
                fontSize: '1rem',
                outline: 'none',
                transition: 'border-color 0.2s',
                boxSizing: 'border-box'
              }}
              onFocus={(e) => {
                e.target.style.borderColor = '#3b82f6';
              }}
              onBlur={(e) => {
                e.target.style.borderColor = '#d1d5db';
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              style={{
                width: '100%',
                padding: '0.75rem',
                borderRadius: '0.5rem',
                border: '1px solid #d1d5db',
                fontSize: '1rem',
                outline: 'none',
                transition: 'border-color 0.2s',
                boxSizing: 'border-box'
              }}
              onFocus={(e) => {
                e.target.style.borderColor = '#3b82f6';
              }}
              onBlur={(e) => {
                e.target.style.borderColor = '#d1d5db';
              }}
            />
          </div>

          <button
            type="submit"
            disabled={isLoading}
            style={{
              padding: '0.75rem',
              backgroundColor: isLoading ? '#9ca3af' : '#3b82f6',
              color: 'white',
              borderRadius: '0.5rem',
              fontWeight: '600',
              border: 'none',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.2s',
              fontSize: '1rem'
            }}
            onMouseOver={(e) => {
              if (!isLoading) {
                const target = e.target as HTMLButtonElement;
                target.style.backgroundColor = '#2563eb';
              }
            }}
            onMouseOut={(e) => {
              if (!isLoading) {
                const target = e.target as HTMLButtonElement;
                target.style.backgroundColor = '#3b82f6';
              }
            }}
          >
            {isLoading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <div style={{ marginTop: '1.5rem', padding: '1rem', backgroundColor: '#f3f4f6', borderRadius: '0.5rem' }}>
          <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0, textAlign: 'center' }}>
            <strong>Demo Credentials:</strong><br />
            Username: <code>admin</code><br />
            Password: <code>admin123</code>
          </p>
        </div>
      </div>
    </div>
  );
}
