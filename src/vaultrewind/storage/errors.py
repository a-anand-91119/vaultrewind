"""Map restic/rclone/provider output to stable, sanitized error codes.

Raw tool output is inspected in memory only and is never stored, logged or
attached to errors; only the resulting code and safe message leave this module.
"""
from __future__ import annotations

import re

from vaultrewind.core.errors import VaultRewindError

# restic exit codes (restic 0.17+ scripting documentation; unknown codes are failures)
EXIT_OK, EXIT_FAILED, EXIT_GO_RUNTIME, EXIT_PARTIAL = 0, 1, 2, 3
EXIT_NO_REPOSITORY, EXIT_LOCKED, EXIT_WRONG_PASSWORD, EXIT_CANCELLED = 10, 11, 12, 130

# (code, safe message, retryable, provider credential state or None)
_RULES: list[tuple[re.Pattern, str, str, bool, str | None]] = [
    (re.compile(r"invalid_grant|token (has been )?expired or revoked|token expired and refresh token is not set|"
                r"refresh token is not set|unauthorized_client|couldn't fetch token", re.IGNORECASE),
     "STORAGE_AUTH_EXPIRED", "Storage authorization expired or was revoked; reconnect the destination.", False,
     "reconnect_required"),
    (re.compile(r"invalid_client", re.IGNORECASE), "STORAGE_CLIENT_INVALID",
     "The configured OAuth client was rejected by the provider.", False, "reconnect_required"),
    (re.compile(r"storageQuotaExceeded|quota.*exceeded|QuotaExceeded|insufficient.?storage|"
                r"uploadLimitExceeded|exceeded your storage", re.IGNORECASE),
     "STORAGE_QUOTA_EXCEEDED", "The storage provider quota is exhausted.", False, "quota_exceeded"),
    (re.compile(r"rateLimitExceeded|userRateLimitExceeded|SlowDown|TooManyRequests|\b429\b|rate limit", re.IGNORECASE),
     "STORAGE_RATE_LIMITED", "The storage provider is rate limiting requests; retry later.", True, "rate_limited"),
    (re.compile(r"InvalidAccessKeyId|SignatureDoesNotMatch|InvalidToken|ExpiredToken|"
                r"The AWS Access Key Id you provided", re.IGNORECASE),
     "STORAGE_CREDENTIALS_INVALID", "The storage credentials were rejected.", False, "credentials_invalid"),
    (re.compile(r"NoSuchBucket|bucket does not exist", re.IGNORECASE), "STORAGE_BUCKET_NOT_FOUND",
     "The configured bucket does not exist or is not visible to these credentials.", False, None),
    (re.compile(r"AccessDenied|Access Denied|\b403\b|Forbidden|insufficientPermissions|permission denied|"
                r"operation not permitted|appNotAuthorizedToFile", re.IGNORECASE),
     "STORAGE_PERMISSION_DENIED", "The storage location denied a required operation.", False, None),
    (re.compile(r"x509:|certificate (signed by unknown authority|is not valid|has expired)|tls: |"
                r"CERTIFICATE_VERIFY_FAILED|certificate verify failed", re.IGNORECASE),
     "STORAGE_TLS_FAILED", "The storage endpoint certificate could not be verified.", False, None),
    (re.compile(r"no space left on device|disk quota exceeded|ENOSPC", re.IGNORECASE),
     "INSUFFICIENT_SPACE", "The storage location has insufficient free space.", False, None),
    (re.compile(r"no such host|connection refused|i/o timeout|network is unreachable|connection reset|"
                r"dial tcp|TLS handshake timeout|context deadline exceeded|EOF while|Could not connect|"
                r"temporary failure in name resolution|server misbehaving", re.IGNORECASE),
     "STORAGE_UNREACHABLE", "The storage endpoint could not be reached; retry later.", True, None),
    (re.compile(r"read-only file system", re.IGNORECASE), "STORAGE_READ_ONLY",
     "The storage location is read-only.", False, None),
]


def classify_output(text: str, default_code: str, default_message: str, *, retryable: bool = False,
                    operation: str | None = None) -> VaultRewindError:
    for pattern, code, message, retry, credential_state in _RULES:
        if pattern.search(text or ""):
            details = {"credential_state": credential_state} if credential_state else {}
            if operation:
                details["operation"] = operation
            return VaultRewindError(code, message, retry, **details)
    details = {"operation": operation} if operation else {}
    return VaultRewindError(default_code, default_message, retryable, **details)


def restic_failure(exit_code: int, stderr: str, operation: str) -> VaultRewindError:
    """Translate a non-successful restic exit into a sanitized error."""
    if exit_code == EXIT_NO_REPOSITORY:
        return VaultRewindError("REPOSITORY_NOT_FOUND", "The storage repository does not exist at its recorded location.",
                                False, operation=operation, exit_code=exit_code)
    if exit_code == EXIT_LOCKED:
        return VaultRewindError("REPOSITORY_LOCKED",
                                "Another process holds the repository lock; it was not forcibly removed.",
                                True, operation=operation, exit_code=exit_code)
    if exit_code == EXIT_WRONG_PASSWORD:
        return VaultRewindError("REPOSITORY_PASSWORD_INVALID",
                                "The repository unlock secret does not open this repository.",
                                False, operation=operation, exit_code=exit_code)
    if exit_code == EXIT_CANCELLED:
        return VaultRewindError("STORAGE_OPERATION_CANCELLED", "The storage operation was cancelled.",
                                True, operation=operation, exit_code=exit_code)
    error = classify_output(stderr, "STORAGE_OPERATION_FAILED", "The storage operation failed.", operation=operation)
    error.details.setdefault("exit_code", exit_code)
    return error


CREDENTIAL_STATE_BY_CODE = {
    "STORAGE_AUTH_EXPIRED": "reconnect_required",
    "STORAGE_CLIENT_INVALID": "reconnect_required",
    "STORAGE_QUOTA_EXCEEDED": "quota_exceeded",
    "STORAGE_RATE_LIMITED": "rate_limited",
    "STORAGE_CREDENTIALS_INVALID": "credentials_invalid",
    "DRIVE_FOLDER_UNAVAILABLE": "folder_unavailable",
}
