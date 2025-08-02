'use client';

import React, { useState } from 'react';
import { runOnServer } from './actions';
import styles from '../../styles/Card.module.css';

export default function AdminPage() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [executionSide, setexecutionSide] = useState<'server' | 'client' | ''>('');

  const handleServerRun = async () => {
    if (!input.trim()) {
      setOutput('Please enter a valid string.');
      setexecutionSide('server');
      return;
    }
    const charCodes = Array.from(input).map((char) => (char as string).charCodeAt(0));
    const result = await runOnServer({ codeArray: JSON.stringify(charCodes) });
    setOutput(result);
    setexecutionSide('server');
  };

  const handleClientRun = () => {
    if (!input.trim()) {
      setOutput('Please enter a valid string.');
      setexecutionSide('client');
      return;
    }
    try {
      const result = new Function(input)();
      setOutput(result !== undefined ? String(result) : 'Code executed successfully.');
      setexecutionSide('client');
    } catch (e: any) {
      setOutput(e.message || 'Error occurred while executing code.');
      setexecutionSide('client');
    }
  };

  return (
    <main style={{ textAlign: 'center', marginTop: 40 }}>
      <h1 className={styles.title}>Admin Game Test Page</h1>
      <div style={{ maxWidth: 600, margin: '0 auto', padding: 20 }}>
        <label htmlFor="str-input" style={{ 
          display: 'block', 
          fontFamily: "'Fira Sans', cursive, sans-serif",
          fontSize: '1.2rem',
          color: '#3a3a7a',
          marginBottom: '10px',
          textAlign: 'left'
        }}>
          Enter a code to run:
        </label>
        <input
          id="str-input"
          type="text"
          value={input}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setInput(e.target.value)}
          style={{ 
            width: '100%', 
            margin: '10px 0', 
            padding: '12px 16px',
            border: '2px solid #3a3a7a',
            borderRadius: '8px',
            fontSize: '1rem',
            fontFamily: "'Fira Sans', cursive, sans-serif",
            outline: 'none',
            transition: 'border-color 0.2s'
          }}
          onFocus={(e: React.FocusEvent<HTMLInputElement>) => (e.target as HTMLInputElement).style.borderColor = '#5a5ad1'}
          onBlur={(e: React.FocusEvent<HTMLInputElement>) => (e.target as HTMLInputElement).style.borderColor = '#3a3a7a'}
        />
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginBottom: 20 }}>
          <button 
            onClick={handleServerRun}
            style={{ 
              padding: '12px 28px', 
              fontFamily: "'Fira Sans', cursive, sans-serif",
              fontSize: '1.1rem',
              border: 'none',
              borderRadius: '8px',
              background: '#3a3a7a',
              color: '#fff',
              cursor: 'pointer',
              transition: 'background 0.2s'
            }}
            onMouseEnter={(e: React.MouseEvent<HTMLButtonElement>) => (e.target as HTMLButtonElement).style.background = '#5a5ad1'}
            onMouseLeave={(e: React.MouseEvent<HTMLButtonElement>) => (e.target as HTMLButtonElement).style.background = '#3a3a7a'}
          >
            Server Run
          </button>
          <button 
            onClick={handleClientRun}
            style={{ 
              padding: '12px 28px', 
              fontFamily: "'Fira Sans', cursive, sans-serif",
              fontSize: '1.1rem',
              border: 'none',
              borderRadius: '8px',
              background: '#3a3a7a',
              color: '#fff',
              cursor: 'pointer',
              transition: 'background 0.2s'
            }}
            onMouseEnter={(e: React.MouseEvent<HTMLButtonElement>) => (e.target as HTMLButtonElement).style.background = '#5a5ad1'}
            onMouseLeave={(e: React.MouseEvent<HTMLButtonElement>) => (e.target as HTMLButtonElement).style.background = '#3a3a7a'}
          >
            Client Run
          </button>
        </div>
        {output && (
          <div style={{ 
            marginTop: 20, 
            padding: '20px',
            backgroundColor: '#fff',
            borderRadius: '16px',
            boxShadow: '0 8px 32px rgba(60,60,120,0.2)',
            textAlign: 'left'
          }}>
            <strong style={{ 
              color: '#3a3a7a',
              fontFamily: "'Fira Sans', cursive, sans-serif",
              fontSize: '1.2rem'
            }}>
              Output ({executionSide}):
            </strong>
            <pre style={{ 
              marginTop: '10px',
              padding: '15px',
              backgroundColor: '#f5f5f5',
              borderRadius: '8px',
              fontFamily: 'monospace',
              fontSize: '0.9rem',
              color: '#333',
              overflow: 'auto'
            }}>
              {output}
            </pre>
          </div>
        )}
      </div>
    </main>
  );
}
