"use client";

export default function DeploymentNotice() {
  return (
    <div style={{
      backgroundColor: '#fef3c7',
      border: '1px solid #f59e0b',
      borderRadius: '0.5rem',
      padding: '1rem',
      marginBottom: '1rem'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <span style={{ fontSize: '1.25rem' }}>⚠️</span>
        <div>
          <p style={{ fontWeight: '600', color: '#92400e', margin: '0 0 0.25rem 0' }}>
            Backend Required for Full Functionality
          </p>
          <p style={{ fontSize: '0.875rem', color: '#92400e', margin: 0 }}>
            This is a frontend-only deployment. For full DNS monitoring functionality, 
            deploy the backend separately on Railway, Render, or Heroku.
          </p>
        </div>
      </div>
    </div>
  );
}
