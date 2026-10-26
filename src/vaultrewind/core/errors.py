def safe_transport_details(value):
    """Only fixed Docker diagnostic categories cross helper/API boundaries."""
    if not isinstance(value, dict):
        return {}
    categories = {"daemon_info", "containers_list", "containers_create", "images_save", "images_load",
                  "volumes_create", "exec_start", "exec_inspect", "exec_create", "containers_inspect",
                  "containers_stop", "containers_start", "containers_update", "containers_rename",
                  "images_inspect", "containers_remove", "volumes_inspect", "volumes_remove",
                  "networks_inspect", "docker_request"}
    details = {}
    if value.get("operation_category") in categories:
        details["operation_category"] = value["operation_category"]
    if value.get("transport_kind") in {"timeout", "http_protocol", "invalid_response", "os_error"}:
        details["transport_kind"] = value["transport_kind"]
    return details


class VaultRewindError(Exception):
    """A deliberately sanitized operational failure suitable for persisted events."""

    def __init__(self, code: str, message: str, retryable: bool = False, **details):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = details

    def as_dict(self):
        result = {"code": self.code, "message": self.message, "retryable": self.retryable}
        details = safe_transport_details(self.details)
        if details:
            result["details"] = details
        return result
