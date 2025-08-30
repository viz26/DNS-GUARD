"use client";
import { useState } from "react";

interface FileAnalysisResult {
  filename: string;
  file_size: number;
  file_type: string;
  md5: string;
  sha1: string;
  sha256: string;
  scan_date: string;
  total_scanners: number;
  positive_scanners: number;
  threat_score: number;
  threat_level: string;
  detected_threats: Array<{
    scanner: string;
    threat_name: string;
    category: string;
  }>;
  analysis_url: string;
}

export default function FileAnalysis() {
  const [file, setFile] = useState<File | null>(null);
  const [results, setResults] = useState<FileAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      // Check file size (VirusTotal has 32MB limit for free API)
      if (selectedFile.size > 32 * 1024 * 1024) {
        setError("File size must be less than 32MB for VirusTotal analysis");
        setFile(null);
        return;
      }
      setFile(selectedFile);
      setError(null);
    }
  };

  const analyzeFile = async () => {
    if (!file) {
      setError("Please select a file to analyze");
      return;
    }

    try {
      setLoading(true);
      setError(null);

      // Create FormData to send file
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(`${backendUrl}/analyze_file`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Failed to analyze file');
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'clean': return '#10b981';
      case 'low': return '#f59e0b';
      case 'medium': return '#f97316';
      case 'high': return '#ef4444';
      case 'critical': return '#991b1b';
      default: return '#6b7280';
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '2rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
          🔍 Analyze Suspicious Files
        </h2>
        <p style={{ color: '#6b7280', fontSize: '1.1rem' }}>
          Upload files to analyze them using VirusTotal's comprehensive threat detection
        </p>
      </div>

      {/* File Upload Section */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '0.75rem',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        border: '1px solid #e5e7eb',
        marginBottom: '2rem'
      }}>
        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '600', color: '#374151' }}>
            Select File to Analyze
          </label>
          <input
            type="file"
            onChange={handleFileChange}
            accept="*/*"
            style={{
              width: '100%',
              padding: '0.75rem',
              border: '2px dashed #d1d5db',
              borderRadius: '0.5rem',
              fontSize: '1rem',
              outline: 'none',
              backgroundColor: '#f9fafb'
            }}
          />
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginTop: '0.5rem' }}>
            Maximum file size: 32MB | Supported formats: All file types
          </div>
        </div>

        {file && (
          <div style={{
            padding: '1rem',
            backgroundColor: '#f0f9ff',
            borderRadius: '0.5rem',
            border: '1px solid #bae6fd',
            marginBottom: '1rem'
          }}>
            <div style={{ fontWeight: '600', color: '#0369a1', marginBottom: '0.25rem' }}>
              Selected File: {file.name}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#0c4a6e' }}>
              Size: {formatFileSize(file.size)} | Type: {file.type || 'Unknown'}
            </div>
          </div>
        )}

        <button
          onClick={analyzeFile}
          disabled={loading || !file}
          style={{
            padding: '0.75rem 2rem',
            backgroundColor: loading || !file ? '#9ca3af' : '#2563eb',
            color: 'white',
            borderRadius: '0.5rem',
            border: 'none',
            cursor: loading || !file ? 'not-allowed' : 'pointer',
            fontSize: '1rem',
            fontWeight: '600',
            transition: 'background-color 0.2s'
          }}
        >
          {loading ? 'Analyzing...' : '🔍 Analyze File'}
        </button>
        
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
          {/* Threat Score Card */}
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
              Threat Analysis Results
            </h3>
            <div style={{ 
              fontSize: '3rem', 
              fontWeight: '700', 
              color: getThreatLevelColor(results.threat_level),
              marginBottom: '0.5rem'
            }}>
              {results.threat_score}%
            </div>
            <div style={{ 
              fontSize: '1.25rem', 
              fontWeight: '600', 
              color: getThreatLevelColor(results.threat_level),
              marginBottom: '1rem'
            }}>
              {results.threat_level.toUpperCase()} THREAT
            </div>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'center', 
              gap: '2rem',
              flexWrap: 'wrap'
            }}>
              <div>
                <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>Detected by</div>
                <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#ef4444' }}>
                  {results.positive_scanners}/{results.total_scanners}
                </div>
                <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>scanners</div>
              </div>
              <div>
                <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>File Size</div>
                <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#1f2937' }}>
                  {formatFileSize(results.file_size)}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>File Type</div>
                <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#1f2937' }}>
                  {results.file_type}
                </div>
              </div>
            </div>
          </div>

          {/* File Details */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '0.75rem',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            border: '1px solid #e5e7eb',
            marginBottom: '2rem'
          }}>
            <h3 style={{ fontSize: '1.25rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
              📋 File Information
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
              <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Filename</div>
                <div style={{ color: '#6b7280', fontFamily: 'monospace' }}>{results.filename}</div>
              </div>
              <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>MD5 Hash</div>
                <div style={{ color: '#6b7280', fontFamily: 'monospace', fontSize: '0.875rem' }}>{results.md5}</div>
              </div>
              <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>SHA1 Hash</div>
                <div style={{ color: '#6b7280', fontFamily: 'monospace', fontSize: '0.875rem' }}>{results.sha1}</div>
              </div>
              <div style={{ padding: '1rem', backgroundColor: '#f9fafb', borderRadius: '0.5rem' }}>
                <div style={{ fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>SHA256 Hash</div>
                <div style={{ color: '#6b7280', fontFamily: 'monospace', fontSize: '0.875rem' }}>{results.sha256}</div>
              </div>
            </div>
          </div>

          {/* Detected Threats */}
          {results.detected_threats.length > 0 && (
            <div style={{
              backgroundColor: 'white',
              padding: '2rem',
              borderRadius: '0.75rem',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
              border: '1px solid #e5e7eb',
              marginBottom: '2rem'
            }}>
              <h3 style={{ fontSize: '1.25rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
                🚨 Detected Threats
              </h3>
              <div style={{ display: 'grid', gap: '0.75rem' }}>
                {results.detected_threats.map((threat, index) => (
                  <div key={index} style={{
                    padding: '1rem',
                    backgroundColor: '#fef2f2',
                    borderRadius: '0.5rem',
                    border: '1px solid #fecaca'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                      <div>
                        <div style={{ fontWeight: '600', color: '#dc2626', marginBottom: '0.25rem' }}>
                          {threat.threat_name}
                        </div>
                        <div style={{ fontSize: '0.875rem', color: '#991b1b' }}>
                          Scanner: {threat.scanner}
                        </div>
                      </div>
                      <div style={{
                        padding: '0.25rem 0.75rem',
                        backgroundColor: '#dc2626',
                        color: 'white',
                        borderRadius: '9999px',
                        fontSize: '0.875rem',
                        fontWeight: '600'
                      }}>
                        {threat.category}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Analysis Link */}
          <div style={{ textAlign: 'center' }}>
            <a
              href={results.analysis_url}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                padding: '1rem 2rem',
                backgroundColor: '#10b981',
                color: 'white',
                borderRadius: '0.5rem',
                textDecoration: 'none',
                fontSize: '1rem',
                fontWeight: '600',
                display: 'inline-block',
                transition: 'background-color 0.2s'
              }}
              onMouseOver={(e) => {
                const target = e.target as HTMLAnchorElement;
                target.style.backgroundColor = '#059669';
              }}
              onMouseOut={(e) => {
                const target = e.target as HTMLAnchorElement;
                target.style.backgroundColor = '#10b981';
              }}
            >
              🔗 View Full Analysis on VirusTotal
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
