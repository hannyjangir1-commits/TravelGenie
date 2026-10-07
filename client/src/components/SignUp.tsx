import React, { useState, useEffect } from 'react';
import type { User } from '../types';
import { signUp } from '../api';

interface SignUpProps {
  onNavigate: (path: string) => void;
  onSuccess: (user: User) => void;
  currentUser: User | null;
}

export const SignUp: React.FC<SignUpProps> = ({ onNavigate, onSuccess, currentUser }) => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
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
    setErrorMessage(null);

    const trimmedName = name.trim();
    const trimmedEmail = email.trim();

    if (!trimmedName) {
      setErrorMessage('Please enter your full name.');
      return;
    }

    if (!trimmedEmail) {
      setErrorMessage('Please enter a valid email address.');
      return;
    }

    if (password.length < 8) {
      setErrorMessage('Password must be at least 8 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match. Please verify your password confirmation.');
      return;
    }

    setIsLoading(true);

    try {
      const response = await signUp(trimmedName, trimmedEmail, password);
      setIsLoading(false);

      if (!response.authenticated || !response.user) {
        setErrorMessage(response.error || 'Failed to create your account. Please try again.');
        return;
      }

      // Success: authenticated -> redirect to main TravelGenie application
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
                <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                <circle cx="8.5" cy="7.5" r="4" />
                <line x1="20" y1="8" x2="20" y2="14" />
                <line x1="23" y1="11" x2="17" y2="11" />
              </svg>
            </div>
            <h1 className="auth-title">Create Account</h1>
            <p className="auth-subtitle">
              Join TravelGenie to create customized itineraries and sync your personal travel intelligence.
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
              <label htmlFor="signup-name" className="field-label">
                Full Name <span className="field-required">*</span>
              </label>
              <div className="field-input-box auth-input-box">
                <svg className="field-icon-left" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                  <circle cx="12" cy="7" r="4" />
                </svg>
                <input
                  id="signup-name"
                  type="text"
                  name="name"
                  autoComplete="name"
                  className="input-control"
                  placeholder="e.g. Alex Morgan"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  disabled={isLoading}
                  required
                />
              </div>
            </div>

            <div className="form-group-item">
              <label htmlFor="signup-email" className="field-label">
                Email Address <span className="field-required">*</span>
              </label>
              <div className="field-input-box auth-input-box">
                <svg className="field-icon-left" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                  <polyline points="22,6 12,13 2,6" />
                </svg>
                <input
                  id="signup-email"
                  type="email"
                  name="email"
                  autoComplete="email"
                  className="input-control"
                  placeholder="e.g. alex@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={isLoading}
                  required
                />
              </div>
            </div>

            <div className="form-group-item">
              <label htmlFor="signup-password" className="field-label">
                Password <span className="field-required">*</span>
              </label>
              <div className="field-input-box auth-input-box">
                <svg className="field-icon-left" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                <input
                  id="signup-password"
                  type="password"
                  name="password"
                  autoComplete="new-password"
                  className="input-control"
                  placeholder="Minimum 8 characters"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isLoading}
                  required
                />
              </div>
            </div>

            <div className="form-group-item">
              <label htmlFor="signup-confirm-password" className="field-label">
                Confirm Password <span className="field-required">*</span>
              </label>
              <div className="field-input-box auth-input-box">
                <svg className="field-icon-left" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                  <polyline points="22 4 12 14.01 9 11.01" />
                </svg>
                <input
                  id="signup-confirm-password"
                  type="password"
                  name="confirmPassword"
                  autoComplete="new-password"
                  className="input-control"
                  placeholder="Confirm your password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={isLoading}
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              className="btn-auth-submit"
              disabled={isLoading}
              id="signup-submit-btn"
            >
              {isLoading ? (
                <>
                  <span className="auth-btn-spinner" aria-hidden="true"></span>
                  <span>Creating Account...</span>
                </>
              ) : (
                <>
                  <span>Sign Up</span>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <line x1="5" y1="12" x2="19" y2="12" />
                    <polyline points="12 5 19 12 12 19" />
                  </svg>
                </>
              )}
            </button>
          </form>

          <div className="auth-footer-prompt">
            <span>Already have an account?</span>{' '}
            <button
              type="button"
              className="auth-link-button"
              onClick={() => onNavigate('/signin')}
              id="goto-signin-link"
            >
              Sign In
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
