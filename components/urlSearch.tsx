"use client";
import { useState } from "react";
import toast from "react-hot-toast";

interface SearchResult {
  domain: string;
  virustotal: boolean;
  googleSafeBrowsing: boolean;
  abuseipdb: boolean;
  threatLevel: string;
  timestamp: string;
}

export default function UrlSearch() {
  const [url, setUrl] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [results, setResults] = useState<SearchResult[]>([]);

  const handleSearch = async () => {
    if (!url.trim()) {
      toast.error("Please enter a URL to search");
      return;
    }

    // Extract domain from URL
    let domain = url.trim();
    if (domain.startsWith("http://") || domain.startsWith("https://")) {
      domain = domain.replace(/^https?:\/\//, "");
    }
    if (domain.includes("/")) {
      domain = domain.split("/")[0];
    }

    // Check if we already analyzed this domain recently
    const existingResult = results.find(r => r.domain === domain);
    if (existingResult) {
      toast.success("Domain already analyzed recently!");
      return;
    }

    setIsSearching(true);
    const loadingToast = toast.loading("Analyzing domain against all APIs...");

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:5000"}/analyze_domain`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ domain }),
      });

      if (!response.ok) {
        throw new Error("Failed to analyze domain");
      }

      const data = await response.json();
      
      const result: SearchResult = {
        domain,
        virustotal: data.virustotal_threat || false,
        googleSafeBrowsing: data.google_safe_browsing_threat || false,
        abuseipdb: data.abuseipdb_threat || false,
        threatLevel: data.threat_level || "Low",
        timestamp: new Date().toLocaleTimeString(),
      };

      setResults(prev => [result, ...prev.slice(0, 4)]); // Keep last 5 results
      toast.success("Domain analysis complete!", { id: loadingToast });
    } catch (error) {
      console.error("Search error:", error);
      toast.error("Failed to analyze domain. Please try again.", { id: loadingToast });
    } finally {
      setIsSearching(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleSearch();
    }
  };

  return (
    <div style={{
      backgroundColor: 'white',
      borderRadius: '0.5rem',
      padding: '1.5rem',
      boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
      border: '1px solid #e5e7eb',
      marginBottom: '2rem'
    }}>
      <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#111827', marginBottom: '1rem' }}>
        🔍 Manual Domain Analysis
      </h3>
      
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem' }}>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Enter URL or domain (e.g., example.com or https://example.com)"
          style={{
            flex: 1,
            padding: '0.75rem',
            borderRadius: '0.5rem',
            border: '1px solid #d1d5db',
            fontSize: '1rem',
            outline: 'none',
            transition: 'border-color 0.2s'
          }}
          onFocus={(e) => {
            e.target.style.borderColor = '#3b82f6';
          }}
          onBlur={(e) => {
            e.target.style.borderColor = '#d1d5db';
          }}
        />
        <button
          onClick={handleSearch}
          disabled={isSearching}
          style={{
            padding: '0.75rem 1.5rem',
            backgroundColor: isSearching ? '#9ca3af' : '#3b82f6',
            color: 'white',
            borderRadius: '0.5rem',
            fontWeight: '600',
            border: 'none',
            cursor: isSearching ? 'not-allowed' : 'pointer',
            transition: 'background-color 0.2s',
            minWidth: '120px'
          }}
          onMouseOver={(e) => {
            if (!isSearching) {
              const target = e.target as HTMLButtonElement;
              target.style.backgroundColor = '#2563eb';
            }
          }}
          onMouseOut={(e) => {
            if (!isSearching) {
              const target = e.target as HTMLButtonElement;
              target.style.backgroundColor = '#3b82f6';
            }
          }}
        >
          {isSearching ? "🔍 Analyzing..." : "🔍 Analyze"}
        </button>
      </div>

      {results.length > 0 && (
        <div>
          <h4 style={{ fontSize: '1rem', fontWeight: '600', color: '#111827', marginBottom: '1rem' }}>
            Recent Analysis Results
          </h4>
          <div style={{ display: 'grid', gap: '1rem' }}>
            {results.map((result, index) => (
              <div key={index} style={{
                backgroundColor: '#f9fafb',
                borderRadius: '0.5rem',
                padding: '1rem',
                border: '1px solid #e5e7eb',
                borderLeft: `4px solid ${
                  result.threatLevel === 'High' ? '#ef4444' : 
                  result.threatLevel === 'Medium' ? '#eab308' : '#10b981'
                }`
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                  <span style={{ fontWeight: '600', color: '#111827' }}>
                    {result.domain}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: '#6b7280' }}>
                    {result.timestamp}
                  </span>
                </div>
                
                <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <span style={{
                    fontSize: '0.75rem',
                    padding: '0.25rem 0.5rem',
                    borderRadius: '0.25rem',
                    backgroundColor: result.virustotal ? '#fee2e2' : '#dbeafe',
                    color: result.virustotal ? '#dc2626' : '#1d4ed8',
                    fontWeight: '500'
                  }}>
                    VirusTotal {result.virustotal ? '🚨' : '✅'}
                  </span>
                  <span style={{
                    fontSize: '0.75rem',
                    padding: '0.25rem 0.5rem',
                    borderRadius: '0.25rem',
                    backgroundColor: result.googleSafeBrowsing ? '#fee2e2' : '#fef3c7',
                    color: result.googleSafeBrowsing ? '#dc2626' : '#d97706',
                    fontWeight: '500'
                  }}>
                    Safe Browsing {result.googleSafeBrowsing ? '🚨' : '✅'}
                  </span>
                  <span style={{
                    fontSize: '0.75rem',
                    padding: '0.25rem 0.5rem',
                    borderRadius: '0.25rem',
                    backgroundColor: result.abuseipdb ? '#fee2e2' : '#fee2e2',
                    color: result.abuseipdb ? '#dc2626' : '#dc2626',
                    fontWeight: '500'
                  }}>
                    AbuseIPDB {result.abuseipdb ? '🚨' : '✅'}
                  </span>
                </div>
                
                <span style={{
                  backgroundColor: result.threatLevel === 'High' ? '#fef2f2' : 
                             result.threatLevel === 'Medium' ? '#fffbeb' : '#f0fdf4',
                  color: result.threatLevel === 'High' ? '#dc2626' : 
                        result.threatLevel === 'Medium' ? '#d97706' : '#16a34a',
                  padding: '0.25rem 0.5rem',
                  borderRadius: '0.25rem',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  textTransform: 'uppercase'
                }}>
                  {result.threatLevel} Threat Level
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
