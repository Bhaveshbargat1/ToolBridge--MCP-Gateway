"""AST-based SQL security guard enforcing strictly read-only parameterized queries."""
import re
from typing import Any, Final, Sequence
import sqlparse
from sqlparse.sql import Statement, Token
from sqlparse.tokens import DDL, DML, Keyword


class SQLSecurityError(PermissionError):
    """Raised when an SQL query violates read-only security constraints or policies."""
    pass


# Forbidden statement types detected by sqlparse
_DISALLOWED_STMT_TYPES: Final[frozenset[str]] = frozenset({
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "CREATE",
    "REPLACE", "EXEC", "EXECUTE", "CALL",
})

# Forbidden keywords anywhere in the query (case-insensitive)
_FORBIDDEN_KEYWORDS: Final[frozenset[str]] = frozenset({
    # DML / Data Mutations
    "INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT",
    # DDL / Schema Modifications
    "DROP", "ALTER", "CREATE", "TRUNCATE", "RENAME",
    # Privilege / Administration
    "GRANT", "REVOKE", "REASSIGN", "OWNED",
    # Table creation via SELECT INTO
    "INTO",
    # Dangerous Administrative & File access functions in Postgres
    "PG_SLEEP", "PG_TERMINATE_BACKEND", "PG_CANCEL_BACKEND",
    "PG_READ_FILE", "PG_WRITE_FILE", "PG_READ_BINARY_FILE",
    "COPY", "LO_EXPORT", "LO_IMPORT",
    # Transaction / Session Manipulation
    "COMMIT", "ROLLBACK", "SAVEPOINT", "DISCARD", "RESET",
    "SET", "VACUUM", "REINDEX", "CLUSTER", "LOCK",
})


class SQLSecurityGuard:
    """Validates SQL statements via AST parsing to guarantee strictly read-only operations."""

    def __init__(self, max_allowed_rows: int = 500, max_query_length: int = 4096) -> None:
        """Initialize the guard with row and query limits.

        Args:
            max_allowed_rows: Maximum result rows permissible for a query.
            max_query_length: Maximum allowed character length for incoming SQL queries.
        """
        self._max_allowed_rows = max_allowed_rows
        self._max_query_length = max_query_length

    @property
    def max_allowed_rows(self) -> int:
        """Return the maximum row limit."""
        return self._max_allowed_rows

    def validate_read_only_query(self, sql_query: str) -> str:
        """Parse and analyze SQL query AST to ensure it is strictly read-only.

        Security checks enforced:
        1. Length limit (DoS defense).
        2. Strict single-statement enforcement (prevents semicolon injection).
        3. Statement type whitelist (must be 'SELECT' or 'UNKNOWN' for CTEs).
        4. Token-level keyword blocklist (catches INSERT, UPDATE, DELETE, INTO, DROP, etc.).
        5. Prohibits dangerous functions (pg_sleep, file access, admin commands).

        Args:
            sql_query: The raw SQL string submitted by client or LLM.

        Returns:
            The sanitized, stripped SQL string if valid.

        Raises:
            SQLSecurityError: If any security validation check fails.
        """
        if not sql_query or not sql_query.strip():
            raise SQLSecurityError("SQL query cannot be empty.")

        cleaned = sql_query.strip().rstrip(";")
        if len(cleaned) > self._max_query_length:
            raise SQLSecurityError(
                f"SQL query exceeds maximum allowed length ({len(cleaned)} > {self._max_query_length})."
            )

        # 1. Parse into AST statements
        statements = sqlparse.parse(sql_query)
        # Filter out empty statements (e.g., trailing whitespace or extra semicolons)
        meaningful_statements = [s for s in statements if str(s).strip().rstrip(";")]

        if not meaningful_statements:
            raise SQLSecurityError("No valid SQL statement found.")

        # 2. Strict Single-Statement Enforcement
        if len(meaningful_statements) > 1:
            raise SQLSecurityError(
                "Multi-statement execution is strictly prohibited. Exactly one query is permitted."
            )

        stmt = meaningful_statements[0]

        # 3. Statement Type Whitelist
        stmt_type = stmt.get_type().upper()
        if stmt_type in _DISALLOWED_STMT_TYPES:
            raise SQLSecurityError(
                f"Mutating statement type '{stmt_type}' is strictly prohibited. Only read-only queries are permitted."
            )

        # Ensure the query begins with an approved read-only keyword (SELECT, WITH, EXPLAIN)
        first_token = self._get_first_keyword(stmt)
        if not first_token or first_token.upper() not in {"SELECT", "WITH", "EXPLAIN"}:
            raise SQLSecurityError(
                f"Prohibited initial SQL keyword '{first_token}'. Query must begin with SELECT, WITH, or EXPLAIN."
            )

        # 4. Token-level Inspection across all flattened tokens
        self._inspect_tokens(stmt)

        return cleaned

    def _get_first_keyword(self, stmt: Statement) -> str | None:
        """Extract the first meaningful keyword token of an SQL statement."""
        for token in stmt.tokens:
            if not token.is_whitespace and not token.ttype == sqlparse.tokens.Comment:
                # Handle CTEs starting with WITH or standard SELECT
                return token.value.strip()
        return None

    def _inspect_tokens(self, stmt: Statement) -> None:
        """Recursively inspect flattened tokens to catch forbidden keywords and commands."""
        for token in stmt.flatten():
            # Check token values
            val = token.value.strip().upper()
            if not val:
                continue

            # Check if token matches forbidden keywords
            if val in _FORBIDDEN_KEYWORDS:
                raise SQLSecurityError(
                    f"Forbidden SQL keyword/command detected: '{val}'. Mutating, DDL, and administrative actions are blocked."
                )

            # Check for function calls like pg_sleep(...) or into ...
            clean_token_str = re.sub(r"[^A-Z0-9_]", " ", val)
            words = clean_token_str.split()
            for word in words:
                if word in _FORBIDDEN_KEYWORDS:
                    raise SQLSecurityError(
                        f"Forbidden keyword '{word}' detected in token: '{token.value}'."
                    )
