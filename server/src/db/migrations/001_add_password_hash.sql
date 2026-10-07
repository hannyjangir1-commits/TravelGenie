-- Migration: 001_add_password_hash.sql
-- Description: Extend users table with password_hash for email/password authentication

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255) NULL;
