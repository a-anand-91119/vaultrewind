"""Read-only Compose dependency inventory; never execute a captured project."""
from pathlib import Path

from .policy import clean_absolute, no_symlink
from .protocol import fail


def validate_compose_dependencies(labels, enrolled):
    files = set(enrolled.value.get("additional_files", {}).values())
    roots = [name for name in labels.get("com.docker.compose.project.config_files", "").split(",") if name]
    if not roots:
        return
    import yaml

    seen = set()
    def enroll(path, base=None, compose=False):
        if not isinstance(path, str) or "$" in path or "\x00" in path:
            fail("UNENROLLED_DEPENDENCY", "Resolve interpolated Compose dependency paths during enrollment.")
        resolved = Path(path) if Path(path).is_absolute() else base / path
        # Parent traversal in the source definition is valid only after exact root-owned enrollment.
        resolved = resolved.absolute()
        normalized = Path(__import__("os").path.normpath(resolved))
        if str(normalized) not in files:
            fail("UNENROLLED_DEPENDENCY", "Enroll every Compose include, environment and secret/configuration file.")
        no_symlink(clean_absolute(str(normalized)))
        if not normalized.is_file():
            fail("UNENROLLED_DEPENDENCY", "A required Compose dependency is not a regular readable file.")
        if compose:
            visit(normalized)

    def file_refs(value, base, compose=False):
        if isinstance(value, str):
            enroll(value, base, compose)
        elif isinstance(value, list):
            for item in value:
                file_refs(item, base, compose)
        elif isinstance(value, dict):
            if "path" not in value:
                fail("UNENROLLED_DEPENDENCY", "Unsupported Compose dependency declaration.")
            enroll(value["path"], base, compose)
            if value.get("env_file"):
                file_refs(value["env_file"], base)
        else:
            fail("UNENROLLED_DEPENDENCY", "Unsupported Compose dependency declaration.")

    def visit(path):
        if path in seen:
            return
        if len(seen) >= 64:
            fail("UNENROLLED_DEPENDENCY", "Compose dependency graph exceeds the supported limit.")
        seen.add(path)
        with path.open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            fail("UNENROLLED_DEPENDENCY", "Compose document exceeds the supported size limit.")
        try:
            # Alias expansion can hide nested dependencies and recursive structures.
            if any(isinstance(token, yaml.tokens.AliasToken) for token in yaml.scan(data)):
                fail("UNSUPPORTED_DEPLOYMENT", "Compose aliases require a flattened enrolled source definition.")
            doc = yaml.safe_load(data)
        except yaml.YAMLError:
            fail("UNSUPPORTED_DEPLOYMENT", "Original Compose document cannot be inventoried safely.")
        if not isinstance(doc, dict):
            fail("UNSUPPORTED_DEPLOYMENT", "Original Compose document must be a mapping.")
        if doc.get("include"):
            file_refs(doc["include"], path.parent, compose=True)
        for service in (doc.get("services") or {}).values():
            if not isinstance(service, dict):
                fail("UNSUPPORTED_DEPLOYMENT", "Invalid Compose service dependency.")
            if service.get("env_file"):
                file_refs(service["env_file"], path.parent)
            if isinstance(service.get("extends"), dict) and service["extends"].get("file"):
                enroll(service["extends"]["file"], path.parent, compose=True)
        for section in ("configs", "secrets"):
            for value in (doc.get(section) or {}).values():
                if isinstance(value, dict) and value.get("file"):
                    enroll(value["file"], path.parent)
        dotenv = path.parent / ".env"
        if dotenv.exists():
            enroll(str(dotenv), path.parent)
    for root in roots:
        enroll(root, compose=True)
