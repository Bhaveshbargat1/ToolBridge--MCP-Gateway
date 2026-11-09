"""AST-based SQL security guard enforcing strictly read-only parameterized queries."""
from __future__ import annotations

import re
from typing import Final
import unicodedata
import sqlparse
from sqlparse.sql import Statement
from sqlparse.tokens import Comment, Literal, String


class SQLSecurityError(PermissionError):
    """Raised when an SQL query violates read-only security constraints or policies."""
    pass


# Forbidden statement types detected by sqlparse
_DISALLOWED_STMT_TYPES: Final[frozenset[str]] = frozenset({
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "CREATE",
    "REPLACE", "EXEC", "EXECUTE", "CALL", "MERGE",
})

# Forbidden keywords, commands, and dangerous functions anywhere in the query (case-insensitive)
_FORBIDDEN_KEYWORDS: Final[frozenset[str]] = frozenset({
    # DML / Data Mutations
    "INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT", "REPLACE",
    # DDL / Schema Modifications
    "DROP", "ALTER", "CREATE", "TRUNCATE", "RENAME",
    # Privilege / Administration
    "GRANT", "REVOKE", "REASSIGN", "OWNED",
    # Table creation via SELECT INTO
    "INTO",
    # Row locking clauses
    "SHARE",
    # Dangerous Administrative & File access functions in Postgres
    "PG_SLEEP", "PG_TERMINATE_BACKEND", "PG_CANCEL_BACKEND",
    "PG_READ_FILE", "PG_WRITE_FILE", "PG_READ_BINARY_FILE", "PG_LS_DIR",
    "COPY", "LO_EXPORT", "LO_IMPORT",
    "QUERY_TO_XML", "SET_CONFIG",
    # Transaction / Session Manipulation
    "COMMIT", "ROLLBACK", "SAVEPOINT", "DISCARD", "RESET",
    "SET", "VACUUM", "REINDEX", "CLUSTER", "LOCK",
    # SQLite administration & extension loading
    "ATTACH", "DETACH", "LOAD_EXTENSION", "PRAGMA",
})


def _is_forbidden_identifier(name: str) -> bool:
    """Check if normalized identifier or function name is blocked."""
    name_upper = name.upper()
    if name_upper in _FORBIDDEN_KEYWORDS:
        return True
    if name_upper.startswith("DBLINK"):
        return True
    return False


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
        1. Unicode normalization (NFKC) to defeat homoglyph and encoding bypasses.
        2. Length limit (DoS defense).
        3. Strict single-statement enforcement (prevents semicolon injection and stacked queries).
        4. Statement type whitelist (must be 'SELECT' or 'UNKNOWN' for CTEs).
        5. Token-level keyword and function blocklist (catches mutations, CTEs, admin functions, locking).
        6. Preserves legitimate string literal contents while blocking unquoted/quoted keywords.

        Args:
            sql_query: The raw SQL string submitted by client or LLM.

        Returns:
            The sanitized, stripped SQL string if valid.

        Raises:
            SQLSecurityError: If any security validation check fails.
        """
        if not sql_query or not sql_query.strip():
            raise SQLSecurityError("SQL query cannot be empty.")

        # Normalize unicode to standard ASCII-compatible representations
        normalized = unicodedata.normalize("NFKC", sql_query)

        cleaned = normalized.strip().rstrip(";")
        if len(cleaned) > self._max_query_length:
            raise SQLSecurityError(
                f"SQL query exceeds maximum allowed length ({len(cleaned)} > {self._max_query_length})."
            )

        # 1. Parse into AST statements
        statements = sqlparse.parse(cleaned)
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
            if not token.is_whitespace and token.ttype not in Comment:
                # Handle CTEs starting with WITH or standard SELECT
                return token.value.strip()
        return None

    def _inspect_tokens(self, stmt: Statement) -> None:
        """Recursively inspect flattened tokens to catch forbidden keywords and commands."""
        for token in stmt.flatten():
            # Skip whitespace and comments
            if token.is_whitespace or token.ttype in Comment:
                continue

            # Skip string literals (e.g. 'active', 'DELETE' as a literal value)
            # but NOT symbols or quoted identifiers
            if token.ttype in Literal.String or token.ttype in String.Single:
                # Double-check it's an actual quoted string literal (starts and ends with ')
                val_raw = token.value.strip()
                if val_raw.startswith("'") and val_raw.endswith("'"):
                    continue

            val = token.value.strip()
            if not val:
                continue

            # Strip identifier quotes (e.g., "set_config", `set_config`, [set_config])
            unquoted = val.strip("\"'`[]")

            # Check whole token value
            if _is_forbidden_identifier(unquoted):
                raise SQLSecurityError(
                    f"Forbidden SQL keyword/command detected: '{unquoted}'. Mutating, DDL, and administrative actions are blocked."
                )

            # Check split sub-words for function calls, schema qualifications (e.g., pg_catalog.set_config)
            clean_token_str = re.sub(r"[^A-Za-z0-9_]", " ", unquoted)
            words = clean_token_str.split()
            for word in words:
                if _is_forbidden_identifier(word):
                    raise SQLSecurityError(
                        f"Forbidden keyword '{word}' detected in token: '{token.value}'."
                    )
