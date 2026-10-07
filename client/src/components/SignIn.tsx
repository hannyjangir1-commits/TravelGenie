import React, { useState, useEffect } from 'react';
import type { User } from '../types';
import { signIn } from '../api';

interface SignInProps {
  onNavigate: (path: string) => void;
  onSuccess: (user: User) => void;
  currentUser: User | null;
}

export const SignIn: React.FC<SignInProps> = ({ onNavigate, onSuccess, currentUser }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // If user is already authenticated, redirect them to the main application
  useEffect(() => {
    if (currentUser) {
      onNavigate('/');
    }
  }, [currentUser, onNavigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password) {
      setErrorMessage('Please enter both your email and password.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await signIn(email.trim(), password);
      setIsLoading(false);

      // A. Email does not exist: redirect clearly to /signup
      if (response.notFound || response.code === 'USER_NOT_FOUND') {
        onNavigate('/signup');
        return;
      }

      // B. Incorrect password or invalid credentials: show error on signin page (no redirect)
      if (!response.authenticated || !response.user) {
        setErrorMessage(response.error || 'Invalid email or password. Please verify your credentials.');
        return;
      }

      // C. Success: authenticated -> redirect to main TravelGenie application
      onSuccess(response.user);
      onNavigate('/');
    } catch {
      setIsLoading(false);
      setErrorMessage('An unexpected network error occurred. Please check your connection.');
    }
  };

  return (
    <div className="auth-view-wrapper">
      <div className="container auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <div className="auth-badge-icon" aria-hidden="true">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
                <polyline points="10 17 15 12 10 7" />
                <line x1="15" y1="12" x2="3" y2="12" />
              </svg>
            </div>
            <h1 className="auth-title">Welcome Back</h1>
            <p className="auth-subtitle">
              Sign in to TravelGenie to access your itineraries and personalized destination intelligence.
            </p>
          </div>

          {errorMessage && (
            <div className="alert-box alert-danger auth-alert" role="alert">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <div>{errorMessage}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="auth-form" noValidate>
            <div className="form-group-item">
              <label htmlFor="signin-email" className="field-label">
                Email Address <span className="field-required">*</span>
              </label>
              <div className="field-input-box auth-input-box">
                <svg className="field-icon-left" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                  <polyline points="22,6 12,13 2,6" />
                </svg>
                <input
                  id="signin-email"
                  type="email"
                  name="email"
                  autoComplete="email"
                  className="input-control"
                  placeholder="e.g. explorer@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={isLoading}
                  required
                />
              </div>
            </div>

            <div className="form-group-item">
              <label htmlFor="signin-password" className="field-label">
                Password <span className="field-required">*</span>
              </label>
              <div className="field-input-box auth-input-box">
                <svg className="field-icon-left" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                <input
                  id="signin-password"
                  type="password"
                  name="password"
                  autoComplete="current-password"
                  className="input-control"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isLoading}
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              className="btn-auth-submit"
              disabled={isLoading}
              id="signin-submit-btn"
            >
              {isLoading ? (
                <>
                  <span className="auth-btn-spinner" aria-hidden="true"></span>
                  <span>Signing In...</span>
                </>
              ) : (
                <>
                  <span>Sign In</span>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <line x1="5" y1="12" x2="19" y2="12" />
                    <polyline points="12 5 19 12 12 19" />
                  </svg>
                </>
              )}
            </button>
          </form>

          <div className="auth-footer-prompt">
            <span>Don't have an account yet?</span>{' '}
            <button
              type="button"
              className="auth-link-button"
              onClick={() => onNavigate('/signup')}
              id="goto-signup-link"
            >
              Create an account
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
