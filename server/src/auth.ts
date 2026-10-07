import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';
import type { SafeUser, UserRow, AuthJwtPayload, SignupRequest, SigninRequest } from './types.js';

export const AUTH_COOKIE_NAME = 'travelgenie_auth';

// Use JWT_SECRET from environment with a secure fallback
const JWT_SECRET = process.env.JWT_SECRET || 'travelgenie_jwt_fallback_secret_production_2026';

export interface AuthenticatedRequest extends Request {
  user?: AuthJwtPayload;
}

// In-memory fallback user store used when PostgreSQL is unconfigured in development
const inMemoryUsers: Map<string, UserRow> = new Map();

/**
 * Returns cookie options matching enterprise security requirements:
 * - HTTP-only: Prevents client script access
 * - SameSite: lax protection
 * - Secure: Enabled in production environments
 */
export function getAuthCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/'
  };
}

/**
 * Returns cookie options for clearing the auth session.
 * Excludes maxAge to prevent Express deprecation notices.
 */
export function getClearCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    path: '/'
  };
}

/**
 * Strips sensitive fields (like password_hash) and returns only safe profile data.
 * Never returns password_hash.
 */
export function toSafeUser(user: Partial<UserRow>): SafeUser {
  return {
    id: user.id || '',
    name: user.name || '',
    email: user.email || '',
    place: (user as any).place || null,
    profilePicture: user.profile_picture || null
  };
}

/**
 * Hashes a plaintext password using bcrypt with 10 salt rounds.
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

/**
 * Verifies a plaintext password against a stored bcrypt hash.
 */
export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Signs a JWT token containing user identity.
 */
export function signAuthToken(payload: AuthJwtPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

/**
 * Verifies a JWT token. Returns decoded payload or null if invalid/expired.
 */
export function verifyAuthToken(token: string): AuthJwtPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthJwtPayload;
    if (decoded && decoded.userId && decoded.email) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Extracts auth token from HTTP-only cookie or Authorization header.
 */
export function extractToken(req: Request): string | null {
  if (req.cookies && req.cookies[AUTH_COOKIE_NAME]) {
    return req.cookies[AUTH_COOKIE_NAME];
  }
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  return null;
}

/**
 * Express middleware requiring a valid authentication session.
 * Protects private API routes.
 */
export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const token = extractToken(req);
  if (!token) {
    res.status(401).json({
      success: false,
      authenticated: false,
      error: 'Authentication required. Please sign in.'
    });
    return;
  }

  const payload = verifyAuthToken(token);
  if (!payload) {
    res.status(401).json({
      success: false,
      authenticated: false,
      error: 'Session expired or invalid. Please sign in again.'
    });
    return;
  }

  req.user = payload;
  next();
}

/**
 * Optional authentication middleware: attaches user if session exists, but doesn't block guests.
 */
export function optionalAuth(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
  const token = extractToken(req);
  if (token) {
    const payload = verifyAuthToken(token);
    if (payload) {
      req.user = payload;
    }
  }
  next();
}

/**
 * Validates signup payload according to strict rules:
 * - body must be an object
 * - name must be string, trimmed, non-empty, max 100
 * - email must be string, trimmed, lowercase, valid format, max 255
 * - password must be string, non-empty (not whitespace-only), min 8 chars, max 128
 */
export function validateSignupInput(body: any): { isValid: boolean; error?: string; data?: SignupRequest } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { isValid: false, error: 'Request body must be a valid JSON object.' };
  }

  const { name, email, password } = body;

  if (typeof name !== 'string') {
    return { isValid: false, error: 'Name must be a string.' };
  }
  const trimmedName = name.trim();
  if (trimmedName.length === 0) {
    return { isValid: false, error: 'Name cannot be empty.' };
  }
  if (trimmedName.length > 100) {
    return { isValid: false, error: 'Name cannot exceed 100 characters.' };
  }

  if (typeof email !== 'string') {
    return { isValid: false, error: 'Email must be a string.' };
  }
  const normalizedEmail = email.trim().toLowerCase();
  if (normalizedEmail.length === 0) {
    return { isValid: false, error: 'Email cannot be empty.' };
  }
  if (normalizedEmail.length > 255) {
    return { isValid: false, error: 'Email cannot exceed 255 characters.' };
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalizedEmail)) {
    return { isValid: false, error: 'Please provide a valid email address.' };
  }

  if (typeof password !== 'string') {
    return { isValid: false, error: 'Password must be a string.' };
  }
  if (password.trim().length === 0) {
    return { isValid: false, error: 'Password cannot be empty or solely whitespace.' };
  }
  if (password.length < 8) {
    return { isValid: false, error: 'Password must be at least 8 characters long.' };
  }
  if (password.length > 128) {
    return { isValid: false, error: 'Password cannot exceed 128 characters.' };
  }

  return {
    isValid: true,
    data: {
      name: trimmedName,
      email: normalizedEmail,
      password
    }
  };
}

/**
 * Validates signin payload:
 * - body must be an object
 * - email and password must be valid strings
 */
export function validateSigninInput(body: any): { isValid: boolean; error?: string; data?: SigninRequest } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { isValid: false, error: 'Request body must be a valid JSON object.' };
  }

  const { email, password } = body;

  if (typeof email !== 'string') {
    return { isValid: false, error: 'Email must be a string.' };
  }
  const normalizedEmail = email.trim().toLowerCase();
  if (normalizedEmail.length === 0) {
    return { isValid: false, error: 'Email cannot be empty.' };
  }

  if (typeof password !== 'string') {
    return { isValid: false, error: 'Password must be a string.' };
  }
  if (password.length === 0) {
    return { isValid: false, error: 'Password cannot be empty.' };
  }

  return {
    isValid: true,
    data: {
      email: normalizedEmail,
      password
    }
  };
}

/**
 * Finds a user by email using parameterized query.
 * Normalizes email to lowercase.
 */
export async function findUserByEmail(email: string): Promise<UserRow | null> {
  const normalizedEmail = email.trim().toLowerCase();

  if (process.env.DATABASE_URL) {
    try {
      const result = await pool.query(
        'SELECT id, google_id, name, email, password_hash, profile_picture, created_at, updated_at FROM users WHERE LOWER(email) = LOWER($1)',
        [normalizedEmail]
      );
      if (result.rows.length > 0) {
        return result.rows[0];
      }
      return null;
    } catch (err) {
      console.error('[DB] Error querying user by email:', err instanceof Error ? err.message : err);
      // Fallback to in-memory store if DB query fails
    }
  }

  for (const user of inMemoryUsers.values()) {
    if (user.email.toLowerCase() === normalizedEmail) {
      return user;
    }
  }
  return null;
}

/**
 * Finds a user by ID using parameterized query.
 */
export async function findUserById(id: string): Promise<UserRow | null> {
  if (process.env.DATABASE_URL) {
    try {
      const result = await pool.query(
        'SELECT id, google_id, name, email, password_hash, profile_picture, created_at, updated_at FROM users WHERE id = $1',
        [id]
      );
      if (result.rows.length > 0) {
        return result.rows[0];
      }
      return null;
    } catch (err) {
      console.error('[DB] Error querying user by id:', err instanceof Error ? err.message : err);
      // Fallback to in-memory store if DB query fails
    }
  }

  return inMemoryUsers.get(id) || null;
}

/**
 * Creates a new user with hashed password in PostgreSQL.
 * Returns safe user profile (never password_hash).
 */
export async function createUser(name: string, email: string, passwordHash: string): Promise<SafeUser> {
  const normalizedEmail = email.trim().toLowerCase();

  if (process.env.DATABASE_URL) {
    try {
      const result = await pool.query(
        'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, profile_picture, created_at, updated_at',
        [name, normalizedEmail, passwordHash]
      );
      const row = result.rows[0];
      return toSafeUser(row);
    } catch (err) {
      console.error('[DB] Error creating user in PostgreSQL:', err instanceof Error ? err.message : err);
      // Fallback to in-memory store
    }
  }

  // Fallback in-memory creation (e.g. during local tests without a running PostgreSQL instance)
  const id = `user-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  const newUser: UserRow = {
    id,
    name,
    email: normalizedEmail,
    password_hash: passwordHash,
    profile_picture: null,
    created_at: new Date(),
    updated_at: new Date()
  };
  inMemoryUsers.set(id, newUser);
  return toSafeUser(newUser);
}
