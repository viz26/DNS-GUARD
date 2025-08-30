"use client";

import { AreaChart, CustomTooltipProps } from "@tremor/react";
import { useState, useEffect } from "react";
import { AllLogData, LogData } from "@/components/homePage";

interface DetailedLogData extends AllLogData {
  virustotal_threat?: boolean;
  google_safe_browsing_threat?: boolean;
  abuseipdb_threat?: boolean;
}
import Controls from "./controls";
const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:5000";

// Check if we're in a browser environment
const isBrowser = typeof window !== 'undefined';

function classNames(...classes: string[]) {
  return classes.filter(Boolean).join(" ");
}

const processLogs = (logs: any[]): LogData => {
  const counts = {
    "High Priority": 0,
    "Medium Priority": 0,
    "Low Priority": 0,
  };

  logs.forEach((log) => {
    if (typeof log === 'string') {
      // Handle old string format
      const threatLevel = log.split("Threat Level:")[1]?.trim();
      if (threatLevel === "High") counts["High Priority"]++;
      else if (threatLevel === "Medium") counts["Medium Priority"]++;
      else if (threatLevel === "Low") counts["Low Priority"]++;
    } else if (log && typeof log === 'object') {
      // Handle new object format
      const threatLevel = log.threat_level || log.ThreatLevel;
      if (threatLevel === "High") counts["High Priority"]++;
      else if (threatLevel === "Medium") counts["Medium Priority"]++;
      else if (threatLevel === "Low") counts["Low Priority"]++;
    }
  });

  return {
    timestamp: new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    }),
    ...counts,
  };
};
const processAllLogs = (logs: any[]): AllLogData[] => {
  return logs.map((log) => {
    if (typeof log === 'string') {
      // Handle old string format: "DNS Query: {domain} | Source: {src_ip} | Destination: {dst_ip} | Threat Level: {threat_level}"
      const parts = log.split(" | ");
      if (parts.length >= 4) {
        const domain = parts[0].replace("DNS Query: ", "");
        const source = parts[1].replace("Source: ", "");
        const destination = parts[2].replace("Destination: ", "");
        const threatLevel = parts[3].replace("Threat Level: ", "");
        
        return {
          timestamp: new Date().toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          }),
          Domain: domain,
          Source: source,
          Destination: destination,
          ThreatLevel: threatLevel,
        };
      }
    } else if (log && typeof log === 'object') {
      // Handle new object format
      return {
        timestamp: new Date(log.timestamp || Date.now()).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        }),
        Domain: log.domain || log.Domain || "Unknown",
        Source: log.source_ip || log.Source || "Unknown",
        Destination: log.destination_ip || log.Destination || "Unknown",
        ThreatLevel: log.threat_level || log.ThreatLevel || "Unknown",
      };
    }
    
    // Return a default entry if parsing fails
    return {
      timestamp: new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      Domain: "Unknown",
      Source: "Unknown",
      Destination: "Unknown",
      ThreatLevel: "Unknown",
    };
  });
};

const fetchLogData = async (): Promise<{
  processLogs: LogData;
  allLogs: AllLogData[];
}> => {
  if (!isBrowser) {
    return {
      processLogs: {
        timestamp: new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        }),
        "High Priority": 0,
        "Medium Priority": 0,
        "Low Priority": 0,
      },
      allLogs: [],
    };
  }

  console.log("Starting fetch...");
  try {
    const start = await fetch(`${BACKEND_URL}/start`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    });
    console.log("Start response:", start.status);
    if (!start.ok) {
      throw new Error("Failed to start");
    }
    
    const response = await fetch(`${BACKEND_URL}/logs`);
    console.log("Logs response:", response.status);
    if (!response.ok) {
      throw new Error("Failed to fetch logs");
    }
    const logs = await response.json();
    console.log("Logs received:", logs);
    
    return {
      processLogs: processLogs(logs),
      allLogs: processAllLogs(logs),
    };
  } catch (error) {
    console.error("Fetch error:", error);
    // Return empty data for production deployment
    if (process.env.NODE_ENV === 'production') {
      console.log("Backend not available in production deployment");
      return {
        processLogs: {
          timestamp: new Date().toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          }),
          "High Priority": 0,
          "Medium Priority": 0,
          "Low Priority": 0,
        },
        allLogs: [],
      };
    }
    throw error;
  }
};
const UPDATE_INTERVAL = 15000; // 15 seconds

export default function Graph({
  shouldStart,
  setShouldStart,
  setLogs,
  setAllLogs,
}: {
  shouldStart: boolean;
  setShouldStart: (shouldStart: boolean) => void;
  logs: LogData[];
  setLogs: React.Dispatch<React.SetStateAction<LogData[]>>;
  allLogs: AllLogData[];
  setAllLogs: React.Dispatch<React.SetStateAction<AllLogData[]>>;
}) {
  const [data, setData] = useState<LogData[]>(() => {
    // Initialize with empty data points
    return Array(20).fill({
      timestamp: new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      "High Priority": 0,
      "Medium Priority": 0,
      "Low Priority": 0,
    });
  });

  const [summary, setSummary] = useState([
    {
      category: "High Priority",
      total: "0/s",
      color: "bg-red-500",
    },
    {
      category: "Medium Priority",
      total: "0/s",
      color: "bg-yellow-500",
    },
    {
      category: "Low Priority",
      total: "0/s",
      color: "bg-green-500",
    },
    {
      category: "Total Logs",
      total: "0/s",
      color: null,
    },
    {
      category: "VirusTotal Flags",
      total: "0",
      color: "bg-blue-500",
    },
    {
      category: "Google Safe Browsing Flags",
      total: "0",
      color: "bg-yellow-500",
    },
    {
      category: "AbuseIPDB Flags",
      total: "0",
      color: "bg-red-500",
    },
  ]);

  useEffect(() => {
    let interval: NodeJS.Timeout;

    const updateData = async () => {
      try {
        const { processLogs, allLogs } = await fetchLogData();
        console.log(allLogs);

        setData((currentData) => {
          const newData = [...currentData.slice(1), processLogs];

          // Count API flags from allLogs
          const virustotalFlags = allLogs.filter(log => 
            typeof log === 'object' && (log as any).virustotal_threat
          ).length;
          
          const googleFlags = allLogs.filter(log => 
            typeof log === 'object' && (log as any).google_safe_browsing_threat
          ).length;
          
          const abuseipdbFlags = allLogs.filter(log => 
            typeof log === 'object' && (log as any).abuseipdb_threat
          ).length;

          // Update summary with latest values
          setSummary((prev) => [
            { ...prev[0], total: `${processLogs["High Priority"]}/s` },
            { ...prev[1], total: `${processLogs["Medium Priority"]}/s` },
            { ...prev[2], total: `${processLogs["Low Priority"]}/s` },
            {
              ...prev[3],
              total: `${
                processLogs["High Priority"] +
                processLogs["Medium Priority"] +
                processLogs["Low Priority"]
              }/s`,
            },
            { ...prev[4], total: `${virustotalFlags}` },
            { ...prev[5], total: `${googleFlags}` },
            { ...prev[6], total: `${abuseipdbFlags}` },
          ]);

          return newData;
        });
        setLogs(data);
        setAllLogs((prev) => [...prev, ...allLogs]);
      } catch (error) {
        console.error("Error fetching log data:", error);
        // If there's an error, stop the fetching
        setShouldStart(false);
      }
    };

    if (shouldStart) {
      // Initial fetch when starting
      updateData();
      // Set up interval for subsequent fetches
      interval = setInterval(updateData, UPDATE_INTERVAL);
    }

    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [shouldStart, setShouldStart]); // Add dependencies

  function logsFormatter(number: number) {
    return `${number}/s`;
  }

  const customTooltip = (props: CustomTooltipProps) => {
    const { payload, active, label } = props;
    if (!active || !payload) return null;
    return (
      <div className="rounded-tremor-default border border-tremor-border bg-tremor-background text-tremor-default shadow-tremor-dropdown dark:border-dark-tremor-border dark:bg-dark-tremor-background dark:shadow-dark-tremor-dropdown">
        <div className="border-b border-tremor-border px-4 py-2 dark:border-dark-tremor-border">
          <p className="font-medium text-tremor-content dark:text-dark-tremor-content">
            {label}
          </p>
        </div>
        <div className="px-4 py-2">
          <div className="mt-2 space-y-1">
            {payload.map((category, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between space-x-8"
              >
                <div className="flex items-center space-x-2">
                  <span
                    className={`h-1 w-3 shrink-0 rounded-sm ${
                      category.dataKey === "High Priority"
                        ? "bg-red-500"
                        : category.dataKey === "Medium Priority"
                        ? "bg-yellow-500"
                        : "bg-green-500"
                    }`}
                    aria-hidden={true}
                  />
                  <p className="text-tremor-content dark:text-dark-tremor-content">
                    {category.dataKey}
                  </p>
                </div>
                <span className="font-medium tabular-nums text-tremor-content-strong dark:text-dark-tremor-content-strong">
                  {logsFormatter(category.value as number)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  return (
    <>
      <div style={{ maxWidth: '100%', margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', marginBottom: '1.5rem' }}>
          <Controls shouldStart={shouldStart} setShouldStart={setShouldStart} />
        </div>
        <div style={{ marginTop: '2rem', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1.5rem' }}>
          {summary.map((item, index) => (
            <div key={index} style={{
              backgroundColor: 'white',
              borderRadius: '0.5rem',
              padding: '1.5rem',
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
              border: '1px solid #e5e7eb'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                {item.color && (
                  <span
                    style={{
                      width: '0.5rem',
                      height: '0.5rem',
                      borderRadius: '50%',
                      backgroundColor: item.color === 'bg-red-500' ? '#ef4444' : 
                                   item.color === 'bg-yellow-500' ? '#eab308' : 
                                   item.color === 'bg-green-500' ? '#10b981' : '#6b7280'
                    }}
                  />
                )}
                <div>
                  <p style={{ fontSize: '1.5rem', fontWeight: '700', color: '#111827', margin: 0 }}>
                    {item.total}
                  </p>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>
                    {item.category}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
        
        {/* Fetching Status Indicator */}
        {shouldStart && (
          <div style={{
            backgroundColor: '#f0fdf4',
            border: '1px solid #bbf7d0',
            borderRadius: '0.5rem',
            padding: '1rem',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem'
          }}>
            <div style={{
              width: '1rem',
              height: '1rem',
              backgroundColor: '#10b981',
              borderRadius: '50%',
              animation: 'pulse 2s infinite'
            }}></div>
            <div>
              <p style={{ fontWeight: '600', color: '#065f46', margin: 0 }}>
                🔍 Actively Monitoring Network Traffic
              </p>
              <p style={{ fontSize: '0.875rem', color: '#047857', margin: 0 }}>
                Real-time DNS analysis in progress... New threats will appear below
              </p>
            </div>
          </div>
        )}

        {/* API Analysis Dashboard */}
        <div style={{ marginTop: '2rem' }}>
          <h3 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#111827', marginBottom: '1rem' }}>
            🔍 API Threat Analysis Dashboard
          </h3>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem' }}>
            {/* VirusTotal Card */}
            <div style={{
              backgroundColor: 'white',
              borderRadius: '0.5rem',
              padding: '1.5rem',
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
              border: '1px solid #e5e7eb',
              borderTop: '4px solid #3b82f6'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                <div style={{ width: '1rem', height: '1rem', backgroundColor: '#3b82f6', borderRadius: '50%' }}></div>
                <div>
                  <p style={{ fontWeight: '700', color: '#111827', margin: 0, fontSize: '1.125rem' }}>VirusTotal</p>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>Malware Detection</p>
                </div>
              </div>
              
              <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
                <div style={{ fontSize: '2rem', fontWeight: '700', color: '#3b82f6', marginBottom: '0.25rem' }}>
                  {summary.find(s => s.category === "VirusTotal Flags")?.total || "0"}
                </div>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>Threats Detected</p>
              </div>
              
              <div style={{ backgroundColor: '#eff6ff', padding: '0.75rem', borderRadius: '0.375rem' }}>
                <p style={{ fontSize: '0.875rem', color: '#1e40af', margin: 0, fontWeight: '500' }}>
                  🦠 Malware Detection: Scans domains against VirusTotal's global threat database
                </p>
              </div>
            </div>
            
            {/* Google Safe Browsing Card */}
            <div style={{
              backgroundColor: 'white',
              borderRadius: '0.5rem',
              padding: '1.5rem',
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
              border: '1px solid #e5e7eb',
              borderTop: '4px solid #eab308'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                <div style={{ width: '1rem', height: '1rem', backgroundColor: '#eab308', borderRadius: '50%' }}></div>
                <div>
                  <p style={{ fontWeight: '700', color: '#111827', margin: 0, fontSize: '1.125rem' }}>Google Safe Browsing</p>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>Phishing Protection</p>
                </div>
              </div>
              
              <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
                <div style={{ fontSize: '2rem', fontWeight: '700', color: '#eab308', marginBottom: '0.25rem' }}>
                  {summary.find(s => s.category === "Google Safe Browsing Flags")?.total || "0"}
                </div>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>Phishing Sites</p>
              </div>
              
              <div style={{ backgroundColor: '#fffbeb', padding: '0.75rem', borderRadius: '0.375rem' }}>
                <p style={{ fontSize: '0.875rem', color: '#92400e', margin: 0, fontWeight: '500' }}>
                  🎣 Phishing Protection: Detects phishing sites and social engineering attacks
                </p>
              </div>
            </div>
            
            {/* AbuseIPDB Card */}
            <div style={{
              backgroundColor: 'white',
              borderRadius: '0.5rem',
              padding: '1.5rem',
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
              border: '1px solid #e5e7eb',
              borderTop: '4px solid #ef4444'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                <div style={{ width: '1rem', height: '1rem', backgroundColor: '#ef4444', borderRadius: '50%' }}></div>
                <div>
                  <p style={{ fontWeight: '700', color: '#111827', margin: 0, fontSize: '1.125rem' }}>AbuseIPDB</p>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>IP Reputation</p>
                </div>
              </div>
              
              <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
                <div style={{ fontSize: '2rem', fontWeight: '700', color: '#ef4444', marginBottom: '0.25rem' }}>
                  {summary.find(s => s.category === "AbuseIPDB Flags")?.total || "0"}
                </div>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>Malicious IPs</p>
              </div>
              
              <div style={{ backgroundColor: '#fef2f2', padding: '0.75rem', borderRadius: '0.375rem' }}>
                <p style={{ fontSize: '0.875rem', color: '#991b1b', margin: 0, fontWeight: '500' }}>
                  🛡️ IP Protection: Checks source IPs against global abuse and reputation databases
                </p>
              </div>
            </div>
          </div>
        </div>
        <AreaChart
          data={data}
          index="timestamp"
          categories={["High Priority", "Medium Priority", "Low Priority"]}
          colors={["red", "yellow", "green"]}
          showLegend={true}
          showGradient={false}
          yAxisWidth={55}
          valueFormatter={logsFormatter}
          customTooltip={customTooltip}
          className="mt-10 hidden h-72 sm:block"
        />
        <AreaChart
          data={data}
          index="timestamp"
          categories={["High Priority", "Medium Priority", "Low Priority"]}
          colors={["red", "yellow", "green"]}
          showLegend={true}
          showGradient={false}
          showYAxis={false}
          startEndOnly={true}
          valueFormatter={logsFormatter}
          customTooltip={customTooltip}
          className="mt-6 h-72 sm:hidden"
        />
      </div>
    </>
  );
}
