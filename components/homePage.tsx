"use client";
import Graph from "@/components/graph";
import LogTable from "@/components/table";
import UrlSearch from "@/components/urlSearch";
import { useState } from "react";
import { Toaster } from 'react-hot-toast';

export interface LogData {
  timestamp: string;
  'High Priority': number;
  'Medium Priority': number;
  'Low Priority': number;
}

export interface AllLogData {
  timestamp: string;
  Domain: string;
  Source: string;
  Destination: string;
  ThreatLevel: string;
}

export default function HomePage() {
  const [shouldStart, setShouldStart] = useState(false);
  const [logs, setLogs] = useState<LogData[]>([]);
  const [allLogs, setAllLogs] = useState<AllLogData[]>([]);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <UrlSearch />
      
      <Graph
        shouldStart={shouldStart}
        setShouldStart={setShouldStart}
        logs={logs}
        setLogs={setLogs}
        allLogs={allLogs}
        setAllLogs={setAllLogs}
      />
      
      <div style={{ marginTop: '2rem' }}>
        <LogTable allLogs={allLogs} />
      </div>
      
      <Toaster />
    </div>
  );
}
