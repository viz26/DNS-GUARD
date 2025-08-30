"use client";
import { useState, useEffect } from "react";

interface ThreatData {
  total_domains: number;
  threat_distribution: {
    high: number;
    medium: number;
    low: number;
  };
  recent_threats: Array<{
    domain: string;
    threat_level: string;
    timestamp: string;
    source_ip: string;
  }>;
  top_malicious_domains: Array<{
    domain: string;
    count: number;
    max_threat: string;
  }>;
  api_usage: {
    virustotal: number;
    google_safe_browsing: number;
    abuseipdb: number;
  };
  security_trends: {
    last_24h: number;
    last_7d: number;
    last_30d: number;
  };
  generated_at: string;
}

export default function ThreatIntelligenceDashboard() {
  const [threatData, setThreatData] = useState<ThreatData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchThreatIntelligence();
  }, []);

  const fetchThreatIntelligence = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${backendUrl}/threat_intelligence`);
      if (!response.ok) {
        throw new Error('Failed to fetch threat intelligence data');
      }
      const data = await response.json();
      setThreatData(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '3rem' }}>
        <div style={{ fontSize: '1.5rem', color: '#6b7280' }}>Loading threat intelligence...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ textAlign: 'center', padding: '3rem' }}>
        <div style={{ fontSize: '1.5rem', color: '#ef4444', marginBottom: '1rem' }}>
          Error: {error}
        </div>
        <button
          onClick={fetchThreatIntelligence}
          style={{
            padding: '0.75rem 1.5rem',
            backgroundColor: '#2563eb',
            color: 'white',
            borderRadius: '0.5rem',
            border: 'none',
            cursor: 'pointer',
            fontSize: '1rem'
          }}
        >
          Retry
        </button>
      </div>
    );
  }

  if (!threatData) {
    return (
      <div style={{ textAlign: 'center', padding: '3rem' }}>
        <div style={{ fontSize: '1.5rem', color: '#6b7280' }}>No threat data available</div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '2rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
          🎯 Threat Intelligence Dashboard
        </h2>
        <p style={{ color: '#6b7280', fontSize: '1.1rem' }}>
          Real-time security insights and threat analysis
        </p>
        <div style={{ fontSize: '0.875rem', color: '#9ca3af', marginTop: '0.5rem' }}>
          Last updated: {new Date(threatData.generated_at).toLocaleString()}
        </div>
      </div>

      {/* Stats Cards */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
        gap: '1.5rem', 
        marginBottom: '2rem' 
      }}>
        <div style={{
          backgroundColor: 'white',
          padding: '1.5rem',
          borderRadius: '0.75rem',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb'
        }}>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>Total Domains Analyzed</div>
          <div style={{ fontSize: '2rem', fontWeight: '700', color: '#1f2937' }}>{threatData.total_domains}</div>
        </div>

        <div style={{
          backgroundColor: 'white',
          padding: '1.5rem',
          borderRadius: '0.75rem',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb'
        }}>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>High Threat Domains</div>
          <div style={{ fontSize: '2rem', fontWeight: '700', color: '#ef4444' }}>{threatData.threat_distribution.high}</div>
        </div>

        <div style={{
          backgroundColor: 'white',
          padding: '1.5rem',
          borderRadius: '0.75rem',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb'
        }}>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>Medium Threat Domains</div>
          <div style={{ fontSize: '2rem', fontWeight: '700', color: '#f59e0b' }}>{threatData.threat_distribution.medium}</div>
        </div>

        <div style={{
          backgroundColor: 'white',
          padding: '1.5rem',
          borderRadius: '0.75rem',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb'
        }}>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>Low Threat Domains</div>
          <div style={{ fontSize: '2rem', fontWeight: '700', color: '#10b981' }}>{threatData.threat_distribution.low}</div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: '2fr 1fr', 
        gap: '2rem',
        marginBottom: '2rem'
      }}>
        {/* Left Column */}
        <div>
          {/* Recent Threats */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '0.75rem',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            border: '1px solid #e5e7eb',
            marginBottom: '1.5rem'
          }}>
            <h3 style={{ fontSize: '1.25rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
              🚨 Recent Threats
            </h3>
            {threatData.recent_threats.length > 0 ? (
              <div>
                {threatData.recent_threats.map((threat, index) => (
                  <div key={index} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0.75rem',
                    backgroundColor: '#f9fafb',
                    borderRadius: '0.5rem',
                    marginBottom: '0.5rem'
                  }}>
                    <div>
                      <div style={{ fontWeight: '600', color: '#1f2937' }}>{threat.domain}</div>
                      <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>Source: {threat.source_ip}</div>
                    </div>
                    <div style={{
                      padding: '0.25rem 0.75rem',
                      borderRadius: '9999px',
                      fontSize: '0.875rem',
                      fontWeight: '600',
                      backgroundColor: threat.threat_level === 'High' ? '#fef2f2' : '#fffbeb',
                      color: threat.threat_level === 'High' ? '#dc2626' : '#d97706'
                    }}>
                      {threat.threat_level}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ textAlign: 'center', color: '#6b7280', padding: '2rem' }}>
                No recent threats detected
              </div>
            )}
          </div>

          {/* Top Malicious Domains */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '0.75rem',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            border: '1px solid #e5e7eb'
          }}>
            <h3 style={{ fontSize: '1.25rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
              🎯 Top Malicious Domains
            </h3>
            {threatData.top_malicious_domains.length > 0 ? (
              <div>
                {threatData.top_malicious_domains.map((domain, index) => (
                  <div key={index} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0.75rem',
                    backgroundColor: '#f9fafb',
                    borderRadius: '0.5rem',
                    marginBottom: '0.5rem'
                  }}>
                    <div>
                      <div style={{ fontWeight: '600', color: '#1f2937' }}>{domain.domain}</div>
                      <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                        Max Threat: {domain.max_threat}
                      </div>
                    </div>
                    <div style={{
                      padding: '0.25rem 0.75rem',
                      backgroundColor: '#dbeafe',
                      color: '#1d4ed8',
                      borderRadius: '9999px',
                      fontSize: '0.875rem',
                      fontWeight: '600'
                    }}>
                      {domain.count} scans
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ textAlign: 'center', color: '#6b7280', padding: '2rem' }}>
                No malicious domains detected
              </div>
            )}
          </div>
        </div>

                          {/* Right Column */}
         <div>
           {/* Security Trends */}
           <div style={{
             backgroundColor: 'white',
             padding: '1.5rem',
             borderRadius: '0.75rem',
             boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
             border: '1px solid #e5e7eb'
           }}>
             <h3 style={{ fontSize: '1.25rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
               📊 Security Trends
             </h3>
             <div>
               <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                 <span style={{ color: '#6b7280' }}>Last 24h</span>
                 <span style={{ fontWeight: '600', color: '#1f2937' }}>{threatData.security_trends.last_24h}</span>
               </div>
               <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                 <span style={{ color: '#6b7280' }}>Last 7 days</span>
                 <span style={{ fontWeight: '600', color: '#1f2937' }}>{threatData.security_trends.last_7d}</span>
               </div>
               <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                 <span style={{ color: '#6b7280' }}>Last 30 days</span>
                 <span style={{ fontWeight: '600', color: '#1f2937' }}>{threatData.security_trends.last_30d}</span>
               </div>
             </div>
           </div>
         </div>
      </div>

      {/* Refresh Button */}
      <div style={{ textAlign: 'center' }}>
        <button
          onClick={fetchThreatIntelligence}
          style={{
            padding: '1rem 2rem',
            backgroundColor: '#2563eb',
            color: 'white',
            borderRadius: '0.5rem',
            border: 'none',
            cursor: 'pointer',
            fontSize: '1rem',
            fontWeight: '600',
            transition: 'background-color 0.2s'
          }}
          onMouseOver={(e) => {
            const target = e.target as HTMLButtonElement;
            target.style.backgroundColor = '#1d4ed8';
          }}
          onMouseOut={(e) => {
            const target = e.target as HTMLButtonElement;
            target.style.backgroundColor = '#2563eb';
          }}
        >
          🔄 Refresh Dashboard
        </button>
      </div>
    </div>
  );
}
