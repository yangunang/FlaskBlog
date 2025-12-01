"""
This module provides rate limiting and account lockout functionality.
"""

import sqlite3
from datetime import datetime, timedelta
from flask import request, abort
from settings import Settings
from utils.log import Log
from utils.securityAuditLogger import SecurityAuditLogger


class RateLimiter:
    """
    Provides rate limiting for login attempts and account lockout.
    """

    @staticmethod
    def _init_rate_limit_table():
        """
        Initialize the rate limiting table if it doesn't exist.
        """
        connection = sqlite3.connect(Settings.DB_USERS_ROOT)
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                attempt_time INTEGER NOT NULL,
                success INTEGER DEFAULT 0
            )
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_identifier_time
            ON login_attempts(identifier, attempt_time)
            """
        )
        connection.commit()
        connection.close()

    @staticmethod
    def _init_request_limit_table():
        """
        Initialize the request limiting table if it doesn't exist.
        """
        connection = sqlite3.connect(Settings.DB_USERS_ROOT)
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                request_time INTEGER NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_request_ip_time
            ON request_logs(ip_address, request_time)
            """
        )
        connection.commit()
        connection.close()

    @staticmethod
    def _get_identifier():
        """
        Get a unique identifier for rate limiting (IP address + user agent).

        Returns:
            str: Identifier for this request
        """
        ip = request.remote_addr or "unknown"
        user_agent = request.headers.get("User-Agent", "")[:100]
        return f"{ip}:{hash(user_agent)}"

    @staticmethod
    def check_rate_limit(userName=None):
        """
        Check if the current request should be rate limited.

        Args:
            userName: Optional username for user-specific rate limiting

        Returns:
            tuple: (is_allowed: bool, retry_after_seconds: int or None, error_message: str or None)
        """
        if not Settings.RATE_LIMIT_ENABLED:
            return True, None, None

        RateLimiter._init_rate_limit_table()

        identifier = RateLimiter._get_identifier()
        if userName:
            identifier = f"{identifier}:{userName}"

        now = int(datetime.now().timestamp())
        window_start = now - Settings.LOCKOUT_DURATION

        connection = sqlite3.connect(Settings.DB_USERS_ROOT)
        cursor = connection.cursor()

        # Count failed attempts in the lockout window
        cursor.execute(
            """
            SELECT COUNT(*) FROM login_attempts
            WHERE identifier = ? AND attempt_time > ? AND success = 0
            """,
            (identifier, window_start),
        )
        failed_attempts = cursor.fetchone()[0]

        # Check if locked out
        if failed_attempts >= Settings.MAX_LOGIN_ATTEMPTS:
            # Find the time of the first failed attempt in this window
            cursor.execute(
                """
                SELECT MIN(attempt_time) FROM login_attempts
                WHERE identifier = ? AND attempt_time > ? AND success = 0
                """,
                (identifier, window_start),
            )
            first_attempt = cursor.fetchone()[0]
            lockout_until = first_attempt + Settings.LOCKOUT_DURATION
            retry_after = lockout_until - now

            if retry_after > 0:
                minutes = retry_after // 60
                Log.warning(
                    f"Rate limit exceeded for {identifier}: {failed_attempts} failed attempts"
                )
                
                # Log to security audit
                SecurityAuditLogger.log_rate_limit(
                    identifier=identifier,
                    ip_address=request.remote_addr,
                    details=f"Login rate limit exceeded: {failed_attempts} failed attempts"
                )
                
                connection.close()
                return (
                    False,
                    retry_after,
                    f"Too many failed attempts. Please try again in {minutes} minutes.",
                )

        connection.close()
        return True, None, None

    @staticmethod
    def record_attempt(userName=None, success=False):
        """
        Record a login attempt.

        Args:
            userName: Optional username
            success: Whether the login was successful
        """
        if not Settings.RATE_LIMIT_ENABLED:
            return

        RateLimiter._init_rate_limit_table()

        identifier = RateLimiter._get_identifier()
        if userName:
            identifier = f"{identifier}:{userName}"

        now = int(datetime.now().timestamp())

        connection = sqlite3.connect(Settings.DB_USERS_ROOT)
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO login_attempts (identifier, attempt_time, success)
            VALUES (?, ?, ?)
            """,
            (identifier, now, 1 if success else 0),
        )

        # If successful, clear old failed attempts for this identifier
        if success:
            cursor.execute(
                """
                DELETE FROM login_attempts
                WHERE identifier = ? AND success = 0
                """,
                (identifier,),
            )
            Log.success(f"Login successful, cleared failed attempts for {identifier}")

        connection.commit()
        connection.close()

    @staticmethod
    def cleanup_old_attempts(days=7):
        """
        Clean up old login attempt records.

        Args:
            days: Number of days to keep records (default 7)
        """
        RateLimiter._init_rate_limit_table()

        cutoff = int((datetime.now() - timedelta(days=days)).timestamp())

        connection = sqlite3.connect(Settings.DB_USERS_ROOT)
        cursor = connection.cursor()
        cursor.execute(
            """DELETE FROM login_attempts WHERE attempt_time < ?""",
            (cutoff,),
        )
        deleted = cursor.rowcount
        connection.commit()
        connection.close()

        if deleted > 0:
            Log.info(f"Cleaned up {deleted} old login attempt records")

    @staticmethod
    def reset_user_lockout(userName):
        """
        Manually reset lockout for a specific user (admin function).

        Args:
            userName: Username to reset
        """
        RateLimiter._init_rate_limit_table()

        connection = sqlite3.connect(Settings.DB_USERS_ROOT)
        cursor = connection.cursor()
        cursor.execute(
            """
            DELETE FROM login_attempts
            WHERE identifier LIKE ? AND success = 0
            """,
            (f"%:{userName}",),
        )
        deleted = cursor.rowcount
        connection.commit()
        connection.close()

        Log.info(f"Reset lockout for user {userName}, cleared {deleted} failed attempts")
        return deleted

    @staticmethod
    def check_request_limit():
        """
        Check global request rate limit.
        Intended to be used as a before_request hook.
        """
        # Skip static files
        if request.path.startswith("/static"):
            return

        connection = sqlite3.connect(Settings.DB_USERS_ROOT)
        cursor = connection.cursor()

        # Get settings from database
        try:
            cursor.execute("SELECT setting_key, setting_value FROM site_settings WHERE setting_key IN ('global_rate_limit_enabled', 'global_rate_limit', 'global_rate_limit_window')")
            settings_rows = cursor.fetchall()
            settings = {row[0]: row[1] for row in settings_rows}
            
            enabled = settings.get("global_rate_limit_enabled", "true").lower() == "true"
            limit = int(settings.get("global_rate_limit", "60"))
            window = int(settings.get("global_rate_limit_window", "60"))
        except Exception:
            # Fallback defaults
            enabled = True
            limit = 60
            window = 60

        if not enabled:
            connection.close()
            return

        RateLimiter._init_request_limit_table()

        ip = request.remote_addr or "unknown"
        now = int(datetime.now().timestamp())
        window_start = now - window

        # Clean up old records (probabilistic cleanup to avoid overhead)
        if now % 100 == 0:
            cursor.execute("DELETE FROM request_logs WHERE request_time < ?", (now - window * 2,))
            connection.commit()

        # Count requests in window
        cursor.execute(
            "SELECT COUNT(*) FROM request_logs WHERE ip_address = ? AND request_time > ?",
            (ip, window_start)
        )
        request_count = cursor.fetchone()[0]

        if request_count >= limit:
            connection.close()
            
            # Log to security audit (only once per window ideally, but simple for now)
            # To avoid spamming audit log, we could check if we recently logged it, 
            # but for now let's just log it.
            SecurityAuditLogger.log_rate_limit(
                identifier=ip,
                ip_address=ip,
                details=f"Global request limit exceeded: {request_count} requests in {window}s"
            )
            
            Log.warning(f"Global rate limit exceeded for {ip}")
            abort(429)

        # Record request
        cursor.execute(
            "INSERT INTO request_logs (ip_address, request_time) VALUES (?, ?)",
            (ip, now)
        )
        connection.commit()
        connection.close()
