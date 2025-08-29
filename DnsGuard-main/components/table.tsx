import { AllLogData } from '@/components/homePage';

interface DetailedLogData {
  timestamp: string;
  domain: string;
  source_ip: string;
  destination_ip: string;
  threat_level: string;
  entropy_score: number;
  virustotal_threat: boolean;
  google_safe_browsing_threat: boolean;
  abuseipdb_threat: boolean;
  threat_details: string[];
}
  
  function classNames(...classes: string[]) {
    return classes.filter(Boolean).join(' ');
  }
  
  export default function LogTable({ allLogs }: { allLogs: AllLogData[] }) {
    console.log("LogTable received logs:", allLogs);
    
    // Sort logs by timestamp in descending order (latest first)
    const sortedLogs = [...allLogs].sort((a, b) => {
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });
    
    console.log("Sorted logs:", sortedLogs);

    const handleDownloadJSON = async () => {
      try {
        const response = await fetch('http://localhost:5000/download_detailed_logs');
        if (response.ok) {
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `dns_guard_report_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
        }
      } catch (error) {
        console.error('Error downloading JSON:', error);
      }
    };

    const handleDownloadCSV = async () => {
      try {
        const response = await fetch('http://localhost:5000/download_csv_logs');
        if (response.ok) {
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `dns_guard_logs_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
        }
      } catch (error) {
        console.error('Error downloading CSV:', error);
      }
    };

    return (
      <>
        <div style={{ marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#111827', marginBottom: '0.25rem' }}>
                🚨 Recent Threats
              </h3>
              <p style={{ color: '#4b5563', marginTop: '0.25rem' }}>
                Latest detected threats and suspicious activities
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={handleDownloadJSON}
                style={{
                  padding: '0.5rem 1rem',
                  backgroundColor: '#3b82f6',
                  color: 'white',
                  borderRadius: '0.5rem',
                  fontWeight: '500',
                  border: 'none',
                  cursor: 'pointer',
                  transition: 'background-color 0.2s'
                }}
                onMouseOver={(e) => {
                  const target = e.target as HTMLButtonElement;
                  target.style.backgroundColor = '#2563eb';
                }}
                onMouseOut={(e) => {
                  const target = e.target as HTMLButtonElement;
                  target.style.backgroundColor = '#3b82f6';
                }}
              >
                📄 Download JSON
              </button>
              <button
                onClick={handleDownloadCSV}
                style={{
                  padding: '0.5rem 1rem',
                  backgroundColor: '#10b981',
                  color: 'white',
                  borderRadius: '0.5rem',
                  fontWeight: '500',
                  border: 'none',
                  cursor: 'pointer',
                  transition: 'background-color 0.2s'
                }}
                onMouseOver={(e) => {
                  const target = e.target as HTMLButtonElement;
                  target.style.backgroundColor = '#059669';
                }}
                onMouseOut={(e) => {
                  const target = e.target as HTMLButtonElement;
                  target.style.backgroundColor = '#10b981';
                }}
              >
                📊 Download CSV
              </button>
            </div>
          </div>
        </div>
        {sortedLogs.length === 0 ? (
          <div style={{
            marginTop: '2rem',
            textAlign: 'center',
            padding: '2rem',
            backgroundColor: '#f9fafb',
            borderRadius: '0.5rem',
            border: '2px dashed #d1d5db'
          }}>
            <div style={{ color: '#6b7280' }}>
              <div style={{ fontSize: '2.25rem', marginBottom: '1rem' }}>📋</div>
              <p style={{ fontSize: '1.125rem', fontWeight: '500', marginBottom: '0.5rem' }}>No logs available</p>
              <p style={{ fontSize: '0.875rem' }}>Start fetching to see real-time DNS query data</p>
            </div>
          </div>
        ) : (
          <div style={{ marginTop: '2rem' }}>
            <div style={{ 
              maxHeight: '600px', 
              overflowY: 'auto', 
              padding: '0.5rem',
              border: '1px solid #e5e7eb',
              borderRadius: '0.5rem',
              backgroundColor: '#f9fafb'
            }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '1rem' }}>
                {sortedLogs.map((log, index) => {
                  // Extract API flags from the log data
                  const logData = allLogs.find(l => l.timestamp === log.timestamp && l.Domain === log.Domain);
                  const virustotalFlag = logData && (logData as any).virustotal_threat;
                  const googleFlag = logData && (logData as any).google_safe_browsing_threat;
                  const abuseipdbFlag = logData && (logData as any).abuseipdb_threat;
                  
                  return (
                    <div key={index} style={{
                      backgroundColor: 'white',
                      borderRadius: '0.5rem',
                      padding: '1.25rem',
                      boxShadow: '0 2px 4px 0 rgba(0, 0, 0, 0.1)',
                      border: '1px solid #e5e7eb',
                      borderLeft: `4px solid ${
                        log.ThreatLevel === 'High' ? '#ef4444' : 
                        log.ThreatLevel === 'Medium' ? '#eab308' : '#10b981'
                      }`
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                        <span style={{
                          backgroundColor: log.ThreatLevel === 'High' ? '#fef2f2' : 
                                     log.ThreatLevel === 'Medium' ? '#fffbeb' : '#f0fdf4',
                          color: log.ThreatLevel === 'High' ? '#dc2626' : 
                                log.ThreatLevel === 'Medium' ? '#d97706' : '#16a34a',
                          padding: '0.375rem 0.75rem',
                          borderRadius: '0.375rem',
                          fontSize: '0.75rem',
                          fontWeight: '700',
                          textTransform: 'uppercase',
                          letterSpacing: '0.05em'
                        }}>
                          {log.ThreatLevel} Threat
                        </span>
                        <span style={{ fontSize: '0.75rem', color: '#6b7280', fontWeight: '500' }}>
                          {log.timestamp}
                        </span>
                      </div>
                      
                      <div style={{ marginBottom: '1rem' }}>
                        <p style={{ fontWeight: '700', color: '#111827', margin: '0 0 0.5rem 0', fontSize: '1rem' }}>
                          Domain: <span style={{ color: '#dc2626' }}>{log.Domain}</span>
                        </p>
                        <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: '0 0 0.25rem 0' }}>
                          Source: <span style={{ fontWeight: '500' }}>{log.Source}</span>
                        </p>
                        <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>
                          Destination: <span style={{ fontWeight: '500' }}>{log.Destination}</span>
                        </p>
                      </div>
                      
                      <div style={{ marginBottom: '0.75rem' }}>
                        <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: '0 0 0.5rem 0', fontWeight: '600' }}>
                          API DETECTIONS:
                        </p>
                        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '0.75rem',
                            padding: '0.375rem 0.75rem',
                            borderRadius: '0.375rem',
                            backgroundColor: virustotalFlag ? '#fee2e2' : '#dbeafe',
                            color: virustotalFlag ? '#dc2626' : '#1d4ed8',
                            fontWeight: '600',
                            border: virustotalFlag ? '1px solid #fecaca' : '1px solid #bfdbfe'
                          }}>
                            🦠 Malware {virustotalFlag ? '🚨' : '✅'}
                          </span>
                          <span style={{
                            fontSize: '0.75rem',
                            padding: '0.375rem 0.75rem',
                            borderRadius: '0.375rem',
                            backgroundColor: googleFlag ? '#fee2e2' : '#fef3c7',
                            color: googleFlag ? '#dc2626' : '#d97706',
                            fontWeight: '600',
                            border: googleFlag ? '1px solid #fecaca' : '1px solid #fed7aa'
                          }}>
                            🎣 Phishing {googleFlag ? '🚨' : '✅'}
                          </span>
                          <span style={{
                            fontSize: '0.75rem',
                            padding: '0.375rem 0.75rem',
                            borderRadius: '0.375rem',
                            backgroundColor: abuseipdbFlag ? '#fee2e2' : '#fee2e2',
                            color: abuseipdbFlag ? '#dc2626' : '#6b7280',
                            fontWeight: '600',
                            border: abuseipdbFlag ? '1px solid #fecaca' : '1px solid #e5e7eb'
                          }}>
                            🛡️ IP Protection {abuseipdbFlag ? '🚨' : '✅'}
                          </span>
                        </div>
                      </div>
                      
                      {log.ThreatLevel === 'High' && (
                        <div style={{
                          backgroundColor: '#fef2f2',
                          border: '1px solid #fecaca',
                          borderRadius: '0.375rem',
                          padding: '0.5rem',
                          marginTop: '0.5rem'
                        }}>
                          <p style={{ fontSize: '0.75rem', color: '#dc2626', margin: 0, fontWeight: '600' }}>
                            ⚠️ High risk domain detected by multiple security APIs
                          </p>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
              
              {sortedLogs.length === 0 && (
                <div style={{ textAlign: 'center', padding: '2rem' }}>
                  <p style={{ color: '#6b7280', fontSize: '1rem' }}>
                    No threats detected yet. Start monitoring to see results.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}
      </>
    );
  }