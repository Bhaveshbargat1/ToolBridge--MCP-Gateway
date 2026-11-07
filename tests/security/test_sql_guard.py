"""Security and penetration test suite for SQLSecurityGuard."""
import pytest
from toolbridge.security.guards.sql import SQLSecurityGuard, SQLSecurityError


@pytest.fixture
def guard() -> SQLSecurityGuard:
    return SQLSecurityGuard(max_allowed_rows=100, max_query_length=1000)


@pytest.mark.security
@pytest.mark.parametrize("valid_query", [
    "SELECT * FROM users",
    "SELECT id, name, email FROM accounts WHERE status = 'active'",
    "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
    "SELECT count(*) FROM logs GROUP BY status_code HAVING count(*) > 10",
    "WITH active_users AS (SELECT * FROM users WHERE active = true) SELECT * FROM active_users",
    "EXPLAIN SELECT * FROM transactions WHERE amount > 100",
    "SELECT id, name FROM products WHERE id = $1",
])
def test_valid_read_only_queries_allowed(guard: SQLSecurityGuard, valid_query: str):
    """Ensure safe SELECT, CTE, and EXPLAIN queries pass validation."""
    validated = guard.validate_read_only_query(valid_query)
    assert validated.startswith("SELECT") or validated.startswith("WITH") or validated.startswith("EXPLAIN")


@pytest.mark.security
@pytest.mark.parametrize("malicious_dml", [
    "INSERT INTO users (id, name) VALUES (1, 'attacker')",
    "UPDATE users SET role = 'admin' WHERE id = 1",
    "DELETE FROM audit_logs WHERE id > 0",
    "MERGE INTO target_table USING source_table ON (id) WHEN MATCHED THEN UPDATE SET col=1",
])
def test_dml_mutations_blocked(guard: SQLSecurityGuard, malicious_dml: str):
    """Verify DML statements (INSERT, UPDATE, DELETE) are rejected."""
    with pytest.raises(SQLSecurityError, match="Mutating statement type|Forbidden SQL keyword|Prohibited initial"):
        guard.validate_read_only_query(malicious_dml)


@pytest.mark.security
@pytest.mark.parametrize("malicious_ddl", [
    "DROP TABLE users",
    "DROP TABLE IF EXISTS users CASCADE",
    "ALTER TABLE users ADD COLUMN password_hash text",
    "TRUNCATE TABLE audit_logs",
    "CREATE TABLE backdoor (id int)",
])
def test_ddl_modifications_blocked(guard: SQLSecurityGuard, malicious_ddl: str):
    """Verify DDL schema modification statements are rejected."""
    with pytest.raises(SQLSecurityError, match="Mutating statement type|Forbidden SQL keyword|Prohibited initial"):
        guard.validate_read_only_query(malicious_ddl)


@pytest.mark.security
@pytest.mark.parametrize("multi_stmt", [
    "SELECT * FROM users; DROP TABLE users;",
    "SELECT 1; UPDATE users SET role='admin';",
    "SELECT id FROM products; DELETE FROM orders;",
])
def test_multi_statement_injection_blocked(guard: SQLSecurityGuard, multi_stmt: str):
    """Verify semicolon-delimited multi-statement queries are strictly blocked."""
    with pytest.raises(SQLSecurityError, match="Multi-statement execution is strictly prohibited"):
        guard.validate_read_only_query(multi_stmt)


@pytest.mark.security
def test_select_into_table_creation_blocked(guard: SQLSecurityGuard):
    """Verify SELECT ... INTO is blocked to prevent table creation attacks."""
    with pytest.raises(SQLSecurityError, match="Forbidden SQL keyword/command detected: 'INTO'|Forbidden keyword 'INTO'"):
        guard.validate_read_only_query("SELECT * INTO malicious_table FROM sensitive_users")


@pytest.mark.security
@pytest.mark.parametrize("admin_attack", [
    "GRANT ALL PRIVILEGES ON DATABASE mydb TO attacker",
    "REVOKE ALL ON users FROM readonly_user",
    "SELECT pg_sleep(10)",
    "SELECT pg_terminate_backend(1234)",
    "SELECT * FROM pg_read_file('server.key')",
    "COPY users TO '/tmp/leak.txt'",
    "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
    "COMMIT",
])
def test_administrative_and_dos_functions_blocked(guard: SQLSecurityGuard, admin_attack: str):
    """Verify privilege escalation, transaction tampering, and DoS functions are blocked."""
    with pytest.raises(SQLSecurityError):
        guard.validate_read_only_query(admin_attack)


@pytest.mark.security
def test_empty_or_excessive_length_query_rejected(guard: SQLSecurityGuard):
    """Verify empty queries and oversized query payloads are rejected."""
    with pytest.raises(SQLSecurityError, match="cannot be empty|No valid SQL statement found"):
        guard.validate_read_only_query("   ;   ")

    oversized = "SELECT * FROM users WHERE " + "x = 1 AND " * 200
    with pytest.raises(SQLSecurityError, match="exceeds maximum allowed length"):
        guard.validate_read_only_query(oversized)
