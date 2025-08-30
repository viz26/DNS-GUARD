"use client";
import toast from "react-hot-toast";

export default function Controls({
  shouldStart,
  setShouldStart,
}: {
  shouldStart: boolean;
  setShouldStart: (shouldStart: boolean) => void;
}) {
  return (
    <div style={{ display: 'flex', gap: '1rem' }}>
      <button
        onClick={() => {
          if (!shouldStart) {
            toast.success("Tracing vulnerabilities...");
          } else {
            toast.error("Stopped tracing vulnerabilities");
          }
          setShouldStart(!shouldStart);
        }}
        style={{
          padding: '0.75rem 1.5rem',
          borderRadius: '0.5rem',
          fontWeight: '600',
          transition: 'all 0.2s',
          boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
          border: 'none',
          cursor: 'pointer',
          color: 'white',
          backgroundColor: shouldStart ? '#ef4444' : '#10b981',
          transform: 'translateZ(0)'
        }}
        onMouseOver={(e) => {
          const target = e.target as HTMLButtonElement;
          target.style.backgroundColor = shouldStart ? '#dc2626' : '#059669';
          target.style.transform = 'scale(1.05)';
          target.style.boxShadow = '0 20px 25px -5px rgba(0, 0, 0, 0.1)';
        }}
        onMouseOut={(e) => {
          const target = e.target as HTMLButtonElement;
          target.style.backgroundColor = shouldStart ? '#ef4444' : '#10b981';
          target.style.transform = 'scale(1)';
          target.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.1)';
        }}
      >
        {shouldStart ? "🛑 Stop Fetching" : "▶️ Start Fetching"}
      </button>
    </div>
  );
}
