-- =============================================================================
-- ToolBridge: Sample PostgreSQL Database & Read-Only User Setup Script
-- =============================================================================
-- Run this script as a PostgreSQL superuser (e.g. postgres) to initialize the
-- demo database and create a locked-down, read-only user for ToolBridge.

-- 1. Create Demo Database
CREATE DATABASE toolbridge_demo;

\c toolbridge_demo;

-- 2. Create Sample Tables
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    company VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    total_amount NUMERIC(10, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    order_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(150) NOT NULL,
    price NUMERIC(10, 2) NOT NULL,
    stock_quantity INTEGER DEFAULT 0
);

-- 3. Populate Seed Data
INSERT INTO customers (name, email, company) VALUES
('Acme Corp', 'contact@acme.com', 'Acme Inc'),
('Stark Industries', 'tony@stark.com', 'Stark Industries'),
('Wayne Enterprises', 'bruce@wayne.com', 'Wayne Enterprises');

INSERT INTO products (sku, name, price, stock_quantity) VALUES
('SRV-001', 'High-Performance Gateway Server', 2499.00, 15),
('SW-002', 'ToolBridge Enterprise License', 999.00, 100),
('ACC-003', 'Hardware Security Module (HSM)', 450.00, 30);

INSERT INTO orders (customer_id, total_amount, status) VALUES
(1, 3498.00, 'completed'),
(2, 999.00, 'processing'),
(3, 450.00, 'completed');

-- 4. Create Dedicated Read-Only User
-- Replace 'SecureReadOnlyPass123!' with your desired password
CREATE USER mcp_readonly WITH PASSWORD 'SecureReadOnlyPass123!';

-- 5. Enforce Least Privilege (Read-Only)
-- Revoke all write/create privileges on schema public
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO mcp_readonly;

-- Revoke all table access by default, then grant SELECT only on explicit table allowlist
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mcp_readonly;
GRANT SELECT ON customers, orders, products TO mcp_readonly;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_readonly;

-- Ensure mcp_readonly has NO superuser or server-level file access roles
REVOKE pg_read_server_files, pg_write_server_files, pg_execute_server_program FROM mcp_readonly;

-- Lock down session characteristics for this user to default to READ ONLY and statement timeout
ALTER ROLE mcp_readonly SET default_transaction_read_only = on;
ALTER ROLE mcp_readonly SET statement_timeout = '10s';
