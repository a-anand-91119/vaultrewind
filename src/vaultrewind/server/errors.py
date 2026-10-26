import re

from fastapi.responses import JSONResponse

MESSAGES = {
    "CREDENTIAL_SESSION_BUSY": "A previous Drive process may still be writing its token. Preserve credential state and its private runtime, then retry after that writer has stopped.",
    "CREDENTIAL_SESSION_UNSAFE": "Private Drive session recovery state could not be verified. Preserve its registry and runtime for credential recovery.",
    "PUBLIC_NETWORK_UNPUBLISHABLE": "The desired restore network cannot publish the approved host ports. Prepare a non-internal NAT bridge and review the target profile.",
    "PUBLIC_READINESS_UNCONFIRMED": "Public endpoint readiness was not proved. Preserve the active generation and reconcile its network without rolling back possible new writes.",
    "PUBLIC_PORTS_UNAVAILABLE": "Docker has not allocated the approved public ports. The active generation is preserved for networking repair.",
    "PUBLIC_ENDPOINT_UNAVAILABLE": "The approved host endpoint did not become reachable. Preserve the active generation and inspect its network.",
    "DESTINATION_IDENTITY_CHANGED": "Existing repositories must keep their storage identity. Create a new destination for another path, endpoint, bucket or Drive folder.",
    "REPOSITORY_IDENTITY_MISMATCH": "The repository does not match the recorded destination identity; preserve existing copies and review its configuration.",
    "REMOTE_JOURNAL_MISSING": "An issued operation has lost its durable host journal. Preserve its generations and reconcile locally before retrying.",
    "RUNNER_CLEANUP_FAILED": "The isolated candidate still needs verified retirement. Cleanup retries retain the runner's physical ownership.",
    "REMOTE_ACCOUNTING_UNAVAILABLE": "The helper could not report complete storage accounting. Update or inspect the host before cleanup.",
    "REMOTE_ACCOUNTING_INVALID": "Remote accounting could not be verified; preserve data and inspect the helper.",
    "REMOTE_CLEANUP_UNCONFIRMED": "The helper has not confirmed cleanup; its retained data remains protected.",
    "CLEANUP_UNSAFE": "The operation is active, uncertain or no longer matches its preserved generation. Reconcile it before cleanup.",
    "CLEANUP_GRACE_PERIOD": "The configured rollback preservation period has not elapsed.",
    "CREDENTIAL_PERSIST_FAILED": "Refreshed provider credentials need durable recovery. Repair private credential storage before discarding its recovery state.",
    "CONTROLLER_RECOVERY_REVIEW_REQUIRED": "Restored unfinished work is held for review; unstarted restores require a new target confirmation.",
    "REMOTE_POLICY_UPDATE_REQUIRED": "Change outage and validation budgets through a reviewed helper activation plan so the remote watchdog enforces the same limits.",
    "ACTIVATION_CREDENTIAL_REQUIRED": "Add a separate administrative SSH activation credential to provision the helper.",
    "HELPER_ACTIVATION_FAILED": "Helper installation failed. Check administrative SSH, Python, Docker, systemd and the reviewed host policy.",
    "HELPER_BUNDLE_UNAVAILABLE": "The packaged helper bundle is missing or its checksums do not match. Rebuild the trusted bundle.",
    "HELPER_NOT_READY": "The compatible helper and host recovery units must be activated and verified first.",
    "LOCAL_MOUNT_MISSING": "The enrolled persistent local storage mount or its identity marker is missing. Reattach it and test the destination.",
    "LOCAL_FILESYSTEM_UNSUPPORTED": "Select a supported persistent filesystem; temporary or disposable filesystems cannot hold backups.",
    "LOCAL_SAFETY_NOT_CONFIGURED": "Configure and test durable encrypted local storage before replacing an existing instance.",
    "INSTANCE_NOT_READY": "Complete supported instance discovery, helper activation and policy setup first.",
    "TARGET_NOT_READY": "Enroll and verify the prepared restore target first.",
    "DISCOVERY_REQUIRED": "Select a supported instance from a completed read-only discovery.",
    "RECONCILIATION_REQUIRED": "Reconcile the earlier host operation and its recovery journal before starting another mutation.",
    "REMOTE_OPERATION_INTERRUPTED": "The interrupted operation must be reconciled from its durable journal before new work.",
    "STORAGE_AUTH_EXPIRED": "Reconnect the storage destination to renew its private authorization.",
    "STORAGE_CREDENTIALS_INVALID": "Update the encrypted storage credentials and test the destination.",
    "STORAGE_PERMISSION_DENIED": "The scoped storage operation was denied. Review the destination permissions.",
    "STORAGE_DELETE_DENIED": "Storage refused deletion. The affected copies remain retained.",
    "STORAGE_NOT_CONFIGURED": "Choose and test at least one required storage destination.",
    "REQUIRED_COPY_FAILED": "A required storage copy failed. Valid copies remain available; retry the failed copy.",
    "OPTIONAL_COPY_FAILED": "A best effort storage copy failed. Required verified copies remain available.",
    "COPY_RETRY_UNAVAILABLE": "The captured retry staging expired and no equivalent complete copy is available. Create a new backup.",
    "NOT_FOUND": "The requested object does not exist.",
    "AUTH_REQUIRED": "Sign in to continue.",
    "FORBIDDEN": "Administrator access is required.",
    "CSRF_INVALID": "Refresh this page and retry the action.",
    "LOGIN_FAILED": "The username or password is incorrect.",
    "RATE_LIMITED": "Too many attempts. Retry after the rate limit window.",
    "VALIDATION_ERROR": "The request contains invalid or unsupported values.",
    "IDEMPOTENCY_CONFLICT": "This idempotency key was already used with different inputs.",
    "IDEMPOTENCY_KEY_REQUIRED": "Supply an Idempotency-Key for this action.",
    "RESOURCE_BUSY": "Another operation owns this physical resource.",
    "TARGET_CHANGED": "The selected content, target or policy changed. Refresh the confirmation.",
    "PLAN_INVALID": "This confirmation is expired, consumed or invalid. Create a new plan.",
    "REVISION_CONFLICT": "The configuration changed. Reload before saving.",
    "SNAPSHOT_INCOMPLETE": "A verified complete copy is required for this action.",
    "BOOTSTRAP_DENIED": "Setup requires the unused private installation bootstrap secret.",
    "SETUP_COMPLETE": "The controller has already been configured.",
    "INSUFFICIENT_SPACE": "The configured space reserve or staging quota is insufficient.",
    "RESTORE_RUNNER_NOT_CONFIGURED": "Configure a dedicated isolated verification runner first.",
    "RETENTION_PROTECTED": "Protection or failure state prevents deleting these copies.",
    "RESTORE_ACTIVATION_UNCERTAIN": "Activation may have occurred. The restored generation is preserved for review.",
    "SOURCE_RECOVERY_FAILED": "The source's intended service state could not be confirmed.",
    "EXTERNAL_PREREQUISITE_MISSING": "A required external integration is not configured or available.",
    "SECRET_BINDING_UNVERIFIED": "A stored secret predates row binding. Run the secret binding migration first.",
    "SECRET_DECRYPT_FAILED": "A stored secret could not be opened with the loaded controller key.",
    "SECRET_UNAVAILABLE": "A required private credential is unavailable.",
    "FENCE_RECONCILIATION_REQUIRED": "The host's fencing state is newer than this controller's. Run host discovery with the administrative credential to adopt it.",
    "STALE_FENCE": "The host rejected a stale fencing token. Reconcile the host before retrying.",
    "IMPORT_PLAN_INVALID": "The import plan is unavailable, already applied or belongs to another job.",
    "CONTROLLER_BACKUP_UNAVAILABLE": "The controller metadata backup could not be produced or verified.",
    "STORAGE_PATH_UNSAFE": "Local storage must use the configured persistent backup mount.",
    "ARTIFACT_UNAVAILABLE": "The export is unavailable or expired.",
    "OAUTH_CLIENT_REQUIRED": "Configure your own Google OAuth client ID and secret before authorizing.",
    "PROVIDER_UNSUPPORTED": "This action does not apply to the selected storage backend.",
    "HOST_CHANGED": "The host identity changed since discovery. Re-run discovery before activation.",
    "POLICY_DROPS_ENROLLED_INSTANCE": "The proposed host policy would drop an already enrolled instance.",
    "INTERNAL_ERROR": "The operation could not complete safely. Inspect its status or contact the administrator.",
}


def safe_code(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", value) else "INTERNAL_ERROR"


def error_body(code, *, retryable=False, phase=None, job_id=None):
    code = safe_code(code)
    return {"error": {"code": code, "message": MESSAGES.get(code, MESSAGES["INTERNAL_ERROR"]),
                      "retryable": bool(retryable), "phase": phase, "job_id": job_id}}


def error_status(code):
    if code == "NOT_FOUND":
        return 404
    if code in {"AUTH_REQUIRED", "LOGIN_FAILED"}:
        return 401
    if code in {"FORBIDDEN", "CSRF_INVALID", "BOOTSTRAP_DENIED"}:
        return 403
    if code == "RATE_LIMITED":
        return 429
    if code in {"INTERNAL_ERROR", "SECRET_FILE_UNAVAILABLE", "EXTERNAL_PREREQUISITE_MISSING",
                "SECRET_BINDING_UNVERIFIED", "SECRET_DECRYPT_FAILED"}:
        return 503
    if code in {"VALIDATION_ERROR", "IDEMPOTENCY_KEY_REQUIRED", "SCHEDULE_INVALID"}:
        return 422
    return 409


def response(exc):
    return JSONResponse(status_code=error_status(exc.code), content=error_body(exc.code, retryable=exc.retryable))
