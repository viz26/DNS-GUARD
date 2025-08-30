"use client";
import { useState } from "react";

interface AnalysisResults {
  domain: string;
  analysis_timestamp: string;
  dns_records: any;
  ssl_certificate: any;
  subdomains: any;
  port_scan: any;
  whois_info: any;
  security_score: {
    score: number;
    level: string;
    issues: string[];
    warnings: string[];
    max_score: number;
  };
}

export default function AdvancedDomainAnalysis() {
  const [domain, setDomain] = useState("");
  const [results, setResults] = useState<AnalysisResults | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("overview");

  const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';

  const analyzeDomain = async () => {
    if (!domain.trim()) {
      setError("Please enter a domain");
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`${backendUrl}/analyze_domain_advanced`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain: domain.trim() }),
      });

      if (!response.ok) {
        throw new Error('Failed to analyze domain');
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getSecurityScoreColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'excellent': return '#10b981';
      case 'good': return '#059669';
      case 'fair': return '#f59e0b';
      case 'poor': return '#dc2626';
      case 'critical': return '#991b1b';
      default: return '#6b7280';
    }
  };

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '2rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
          🔍 Advanced Domain Analysis
        </h2>
        <p style={{ color: '#6b7280', fontSize: '1.1rem' }}>
          Comprehensive security analysis with DNS records, SSL certificates, subdomains, and more
        </p>
      </div>

      {/* Input Section */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '0.75rem',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        border: '1px solid #e5e7eb',
        marginBottom: '2rem'
      }}>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '600', color: '#374151' }}>
              Domain to Analyze
            </label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="Enter domain (e.g., google.com)"
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #d1d5db',
                borderRadius: '0.5rem',
                fontSize: '1rem',
                outline: 'none'
              }}
              onKeyPress={(e) => e.key === 'Enter' && analyzeDomain()}
            />
          </div>
          <button
            onClick={analyzeDomain}
            disabled={loading}
            style={{
              padding: '0.75rem 2rem',
              backgroundColor: loading ? '#9ca3af' : '#2563eb',
              color: 'white',
              borderRadius: '0.5rem',
              border: 'none',
              cursor: loading ? 'not-allowed' : 'pointer',
              fontSize: '1rem',
              fontWeight: '600',
              transition: 'background-color 0.2s'
            }}
          >
            {loading ? 'Analyzing...' : '🔍 Analyze Domain'}
          </button>
        </div>
        
        {error && (
          <div style={{ 
            marginTop: '1rem', 
            padding: '0.75rem', 
            backgroundColor: '#fef2f2', 
            color: '#dc2626', 
            borderRadius: '0.5rem',
            border: '1px solid #fecaca'
          }}>
            {error}
          </div>
        )}
      </div>

      {/* Results Section */}
      {results && (
        <div>
          {/* Security Score Card */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '0.75rem',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            border: '1px solid #e5e7eb',
            marginBottom: '2rem',
            textAlign: 'center'
          }}>
            <h3 style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
              Security Score
            </h3>
            <div style={{ 
              fontSize: '3rem', 
              fontWeight: '700', 
              color: getSecurityScoreColor(results.security_score.level),
              marginBottom: '0.5rem'
            }}>
              {results.security_score.score}/{results.security_score.max_score}
            </div>
            <div style={{ 
              fontSize: '1.25rem', 
              fontWeight: '600', 
              color: getSecurityScoreColor(results.security_score.level),
              marginBottom: '1rem'
            }}>
              {results.security_score.level}
            </div>
            
            {/* Issues and Warnings */}
            {(results.security_score.issues.length > 0 || results.security_score.warnings.length > 0) && (
              <div style={{ display: 'flex', gap: '2rem', justifyContent: 'center', flexWrap: 'wrap' }}>
                {results.security_score.issues.length > 0 && (
                  <div>
                    <h4 style={{ color: '#dc2626', marginBottom: '0.5rem' }}>🚨 Critical Issues</h4>
                    <ul style={{ textAlign: 'left', color: '#dc2626' }}>
                                              {results.security_score.issues.map((issue: any, index) => (
                        <li key={index}>{issue}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {results.security_score.warnings.length > 0 && (
                  <div>
                    <h4 style={{ color: '#f59e0b', marginBottom: '0.5rem' }}>⚠️ Warnings</h4>
                    <ul style={{ textAlign: 'left', color: '#f59e0b' }}>
                                              {results.security_score.warnings.map((warning: any, index) => (
                        <li key={index}>{warning}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Analysis Tabs */}
          <div style={{
            backgroundColor: 'white',
            borderRadius: '0.75rem',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            border: '1px solid #e5e7eb',
            overflow: 'hidden'
          }}>
            {/* Tab Navigation */}
            <div style={{ 
              display: 'flex', 
              borderBottom: '1px solid #e5e7eb',
              backgroundColor: '#f9fafb'
            }}>
              {['overview', 'dns', 'ssl', 'subdomains', 'ports', 'whois'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  style={{
                    padding: '1rem 1.5rem',
                    backgroundColor: activeTab === tab ? 'white' : 'transparent',
                    color: activeTab === tab ? '#2563eb' : '#6b7280',
                    border: 'none',
                    cursor: 'pointer',
                    fontWeight: '600',
                    borderRight: '1px solid #e5e7eb'
                  }}
                >
                  {tab === 'overview' && '📊 Overview'}
                  {tab === 'dns' && '🌐 DNS Records'}
                  {tab === 'ssl' && '🔒 SSL Certificate'}
                  {tab === 'subdomains' && '🔗 Subdomains'}
                  {tab === 'ports' && '🚪 Port Scan'}
                  {tab === 'whois' && '📋 WHOIS Info'}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div style={{ padding: '2rem' }}>
              {activeTab === 'overview' && (
                <div>
                  <h3 style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
                    Analysis Overview
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                    <div style={{ padding: '1rem', backgroundColor: '#f3f4f6', borderRadius: '0.5rem' }}>
                      <div style={{ fontWeight: '600', color: '#374151' }}>Domain</div>
                      <div style={{ color: '#6b7280' }}>{results.domain}</div>
                    </div>
                    <div style={{ padding: '1rem', backgroundColor: '#f3f4f6', borderRadius: '0.5rem' }}>
                      <div style={{ fontWeight: '600', color: '#374151' }}>Analysis Time</div>
                      <div style={{ color: '#6b7280' }}>{new Date(results.analysis_timestamp).toLocaleString()}</div>
                    </div>
                    <div style={{ padding: '1rem', backgroundColor: '#f3f4f6', borderRadius: '0.5rem' }}>
                      <div style={{ fontWeight: '600', color: '#374151' }}>Security Level</div>
                      <div style={{ color: getSecurityScoreColor(results.security_score.level) }}>
                        {results.security_score.level}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'dns' && (
                <div>
                  <h3 style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
                    DNS Records
                  </h3>
                  {results.dns_records.error ? (
                    <div style={{ color: '#dc2626' }}>{results.dns_records.error}</div>
                  ) : (
                    <div style={{ display: 'grid', gap: '1rem' }}>
                                              {Object.entries(results.dns_records).map(([recordType, records]: [string, any]) => (
                        <div key={recordType} style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                          <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>{recordType} Records</div>
                          {Array.isArray(records) && records.length > 0 ? (
                            <div style={{ color: '#6b7280' }}>
                              {records.map((record: any, index) => (
                                <div key={index}>{record}</div>
                              ))}
                            </div>
                          ) : (
                            <div style={{ color: '#9ca3af' }}>No {recordType} records found</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'ssl' && (
                <div>
                  <h3 style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
                    SSL Certificate
                  </h3>
                  {results.ssl_certificate.error ? (
                    <div style={{ color: '#dc2626' }}>{results.ssl_certificate.error}</div>
                  ) : (
                    <div style={{ display: 'grid', gap: '1rem' }}>
                      <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                        <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Certificate Status</div>
                        <div style={{ 
                          color: results.ssl_certificate.is_expired ? '#dc2626' : 
                                 results.ssl_certificate.is_expiring_soon ? '#f59e0b' : '#10b981'
                        }}>
                          {results.ssl_certificate.is_expired ? '❌ Expired' : 
                           results.ssl_certificate.is_expiring_soon ? '⚠️ Expiring Soon' : '✅ Valid'}
                        </div>
                      </div>
                      <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                        <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Days Until Expiry</div>
                        <div style={{ color: '#6b7280' }}>{results.ssl_certificate.days_until_expiry} days</div>
                      </div>
                      <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                        <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Issuer</div>
                        <div style={{ color: '#6b7280' }}>
                          {results.ssl_certificate.issuer?.organizationName || 'Unknown'}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'subdomains' && (
                <div>
                  <h3 style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
                    Subdomain Enumeration
                  </h3>
                  {results.subdomains.error ? (
                    <div style={{ color: '#dc2626' }}>{results.subdomains.error}</div>
                  ) : (
                    <div>
                      <div style={{ marginBottom: '1rem' }}>
                        <span style={{ fontWeight: '600', color: '#374151' }}>
                          Found {results.subdomains.total_found} subdomains
                        </span>
                        <span style={{ color: '#6b7280', marginLeft: '1rem' }}>
                          (searched {results.subdomains.searched_count} common subdomains)
                        </span>
                      </div>
                      {results.subdomains.subdomains.length > 0 ? (
                        <div style={{ display: 'grid', gap: '0.5rem' }}>
                          {results.subdomains.subdomains.map((subdomain: any, index) => (
                            <div key={index} style={{ 
                              padding: '0.75rem', 
                              backgroundColor: '#f0f9ff', 
                              borderRadius: '0.5rem',
                              border: '1px solid #bae6fd'
                            }}>
                              <div style={{ color: '#0369a1', fontWeight: '500' }}>{subdomain.subdomain}</div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ color: '#9ca3af', textAlign: 'center', padding: '2rem' }}>
                          No subdomains found
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'ports' && (
                <div>
                  <h3 style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
                    Port Scan Results
                  </h3>
                  {results.port_scan.error ? (
                    <div style={{ color: '#dc2626' }}>{results.port_scan.error}</div>
                  ) : (
                    <div>
                      <div style={{ marginBottom: '1rem' }}>
                        <span style={{ fontWeight: '600', color: '#374151' }}>
                          Scanned {results.port_scan.total_ports_scanned} ports
                        </span>
                        <span style={{ color: '#6b7280', marginLeft: '1rem' }}>
                          ({results.port_scan.open_count} open, {results.port_scan.closed_count} closed)
                        </span>
                      </div>
                      {results.port_scan.open_ports.length > 0 ? (
                        <div style={{ display: 'grid', gap: '0.5rem' }}>
                          {results.port_scan.open_ports.map((port: any, index) => (
                            <div key={index} style={{ 
                              padding: '0.75rem', 
                              backgroundColor: '#fef3c7', 
                              borderRadius: '0.5rem',
                              border: '1px solid #fbbf24'
                            }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ color: '#92400e', fontWeight: '500' }}>
                                  Port {port.port} ({port.service})
                                </span>
                                <span style={{ 
                                  padding: '0.25rem 0.5rem', 
                                  backgroundColor: '#fbbf24', 
                                  color: '#92400e',
                                  borderRadius: '0.25rem',
                                  fontSize: '0.875rem',
                                  fontWeight: '600'
                                }}>
                                  OPEN
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ color: '#10b981', textAlign: 'center', padding: '2rem' }}>
                          ✅ All scanned ports are closed
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'whois' && (
                <div>
                  <h3 style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
                    WHOIS Information
                  </h3>
                  {results.whois_info.error ? (
                    <div style={{ color: '#dc2626' }}>{results.whois_info.error}</div>
                  ) : (
                    <div style={{ display: 'grid', gap: '1rem' }}>
                      <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                        <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Registrar</div>
                        <div style={{ color: '#6b7280' }}>{results.whois_info.registrar || 'Unknown'}</div>
                      </div>
                      <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                        <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Organization</div>
                        <div style={{ color: '#6b7280' }}>{results.whois_info.org || 'Unknown'}</div>
                      </div>
                      <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                        <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Country</div>
                        <div style={{ color: '#6b7280' }}>{results.whois_info.country || 'Unknown'}</div>
                      </div>
                      <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                        <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Creation Date</div>
                        <div style={{ color: '#6b7280' }}>
                          {results.whois_info.creation_date ? 
                            new Date(results.whois_info.creation_date).toLocaleDateString() : 'Unknown'}
                        </div>
                      </div>
                      <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                        <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Expiration Date</div>
                        <div style={{ color: '#6b7280' }}>
                          {results.whois_info.expiration_date ? 
                            new Date(results.whois_info.expiration_date).toLocaleDateString() : 'Unknown'}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
