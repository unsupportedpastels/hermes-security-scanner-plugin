"""Bounded agent-facing adapters. Authorization is never an agent-tool input."""
from __future__ import annotations

import json
from typing import Callable

from .errors import SecurityError, ValidationError

MAX_RESULT_CHARS = 60_000
MAX_INPUT_BYTES = 2 * 1024 * 1024


def _field(kind, description, **constraints):
    return {"type": kind, "description": description, **constraints}


_SCAN = _field("string", "Existing scan ID returned by start.", minLength=1)
_OBJECTS = {"type": "array", "items": {"type": "object"}}


def _schema(suffix, description, properties, required):
    return {"name": "security_scan_" + suffix, "description": description,
            "parameters": {"type": "object", "properties": properties,
                           "required": required, "additionalProperties": False}}


TOOL_SCHEMAS = [
    _schema("start", "Start a repository review and snapshot its inventory before analysis. Defaults to static; never execute target code or imply validation consent.", {
        "path": _field("string", "Local target directory; never the home or filesystem root.", minLength=1),
        "mode": _field("string", "Review mode; use deep only when requested.", enum=["standard", "deep", "diff"], default="standard"),
        "safety_level": _field("string", "Safety policy; selecting a level does not grant authorization.", enum=["static", "local-safe", "active-authorized"], default="static"),
        "scope": _field("array", "In-scope path globs.", items={"type": "string"}),
        "base": _field("string", "Pinned diff base revision."),
        "head": _field("string", "Pinned diff head revision."),
    }, ["path"]),
    _schema("get", "Read scan state or one paginated section before continuing a review. Read every page; incomplete coverage is not a clean result.", {
        "scan_id": _SCAN,
        "section": _field("string", "Section to read: summary (scan header: digest, methodology, submit instructions, packet IDs), packets, inventory, candidates, coverage, workers, detectors, validations, chains, activity, findings, manifest, or report. Use summary then packets when a start or get result is truncated."),
        "limit": _field("integer", "Maximum records per page; reduce if the response is truncated.", minimum=1, maximum=500, default=50),
        "offset": _field("integer", "Zero-based page offset.", minimum=0, default=0),
    }, ["scan_id"]),
    _schema("checkpoint", "Save review coverage and an optional progress note during analysis. Mark units reviewed only when supported by actual review.", {
        "scan_id": _SCAN, "coverage": {**_OBJECTS, "description": "Coverage units with unit, state, and note."},
        "note": _field("string", "Progress note without literal secrets.", maxLength=4000),
    }, ["scan_id", "coverage"]),
    _schema("submit_worker_result", "Submit a worker result after reviewing its assigned snapshot. Citations must match that snapshot; never include literal secrets or invented evidence.", {
        "payload": _field("object", "Canonical worker result with scanId, attemptId, workerRole, snapshotDigest, methodologyVersion, candidates and coverage."),
    }, ["payload"]),
    _schema("import_detector_results", "Import SARIF or run an approved static detector for a scan. Detector claims remain candidates; do not execute target application code.", {
        "scan_id": _SCAN, "detector": _field("string", "Registered detector name."),
        "sarif_path": _field("string", "Local SARIF file path to import."),
        "run": _field("boolean", "Run the named detector instead of only importing output.", default=False),
    }, ["scan_id"]),
    _schema("record_validations", "Record validation receipts or evaluate plans after static analysis. This tool never grants consent; local execution or active probes require prior user authorization.", {
        "scan_id": _SCAN, "receipts": {**_OBJECTS, "description": "Validation receipts to record; the service checks their evidence."},
        "plans": {**_OBJECTS, "description": "Validation plans subject to the existing scan policy and grants."},
    }, ["scan_id"]),
    _schema("record_chains", "Compose and record evidence-linked chains after primitive findings are reviewed. Explanations cannot invent edges or upgrade unsupported evidence.", {
        "scan_id": _SCAN, "explanations": _field("object", "Optional title and summary explanations keyed by existing chain ID."),
    }, ["scan_id"]),
    _schema("finalize", "Validate and seal a reviewed scan into immutable reports. Call after workers finish; preserve missing coverage and never report a partial scan as clean.", {"scan_id": _SCAN}, ["scan_id"]),
    _schema("cancel", "Cancel an unfinished scan when the review must stop. Retain collected evidence; sealed reports cannot be changed.", {"scan_id": _SCAN}, ["scan_id"]),
    _schema("export", "Read a sealed scan export for delivery after finalization. Keep secret values redacted and do not modify the sealed artifacts.", {
        "scan_id": _SCAN, "fmt": _field("string", "Export format.", enum=["md", "sarif", "json", "csv"]),
    }, ["scan_id", "fmt"]),
]
_SCHEMAS = {schema["name"]: schema for schema in TOOL_SCHEMAS}
_METHODS = {"start": "start_scan", "get": "get_scan"}


def _validate(value, schema):
    """Validate the small JSON Schema subset used by these adapter schemas."""
    kind = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}
    if kind and (not isinstance(value, types[kind]) or (kind == "integer" and isinstance(value, bool))):
        raise ValidationError("Argument has an invalid JSON type")
    if "enum" in schema and value not in schema["enum"]:
        raise ValidationError("Argument is not an allowed value")
    if kind == "object":
        properties = schema.get("properties", {})
        if any(key not in value for key in schema.get("required", [])):
            raise ValidationError("Required argument is missing")
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            raise ValidationError("Unknown argument is not allowed")
        for key in value.keys() & properties.keys():
            _validate(value[key], properties[key])
    elif kind == "array":
        for item in value:
            _validate(item, schema.get("items", {}))
    elif kind == "integer":
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise ValidationError("Argument is outside the allowed range")
    elif kind == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", MAX_INPUT_BYTES):
            raise ValidationError("Argument has an invalid length")


def export_document(result):
    """Normalize the report library's byte export without lossy stringification."""
    if isinstance(result, tuple) and len(result) == 3:
        content, content_type, filename = result
        return {"content": content.decode("utf-8") if isinstance(content, bytes) else content,
                "content_type": content_type, "filename": filename}
    if isinstance(result, bytes):
        return {"content": result.decode("utf-8")}
    return result


def error_envelope(exc):
    """Expose expected domain errors; hide unexpected exception details."""
    if isinstance(exc, SecurityError):
        from .target.redact import redact_secrets
        message = redact_secrets(str(exc))[0][:1000]
        return {"ok": False, "error": {"code": exc.code, "message": message}}
    return {"ok": False, "error": {"code": "internal_error", "message": "Security operation failed"}}


def encode_result(result, *, args=None, cap=True):
    """Return valid JSON even when a result exceeds the model-facing limit."""
    envelope = {"ok": True, "result": export_document(result)}
    raw = json.dumps(envelope, ensure_ascii=True, allow_nan=False)
    if cap and len(raw) > MAX_RESULT_CHARS:
        args = args or {}
        # Do not cut JSON mid-string or suggest that omitted records were returned.
        envelope = {"ok": True, "truncated": True, "result_omitted": True,
                    "pagination_hint": "Use security_scan_get with section 'summary' for the scan header, then section 'packets' (or another section) with a smaller limit at the same offset; use CLI get or export --out for full output.",
                    "limit": max(1, args.get("limit", 50) // 2), "offset": args.get("offset", 0)}
        scan_id = args.get("scan_id")
        if not scan_id and isinstance(result, dict):
            scan_id = result.get("scanId", result.get("scan_id"))
        if isinstance(scan_id, str) and len(scan_id) <= 256:
            envelope["scan_id"] = scan_id
        if isinstance(result, dict):
            # Keep the small header fields (digest, methodology, submit instructions, packet IDs) so a
            # truncated start/get result is still actionable without the omitted bulk.
            header: dict = {k: v for k, v in result.items()
                            if isinstance(v, (str, int, float, bool)) and len(json.dumps(v)) <= 512}
            if isinstance(result.get("submit"), dict):
                header["submit"] = result["submit"]
            if isinstance(result.get("packets"), list):
                header["packetIds"] = [p.get("packetId") for p in result["packets"] if isinstance(p, dict)][:500]
            raw_header = json.dumps(export_document(header), ensure_ascii=True, allow_nan=False)
            if header and len(raw_header) <= 8_000:
                envelope["header"] = json.loads(raw_header)
        raw = json.dumps(envelope)
    return raw


def make_handler(name: str, get_service: Callable):
    """Hermes tools.registry calls handler(args: dict, **kwargs) -> str."""
    schema = _SCHEMAS[name]["parameters"]
    suffix = name.removeprefix("security_scan_")

    def handler(args, **kwargs):
        del kwargs  # task_id / parent_agent are host metadata, not service input.
        try:
            _validate(args, schema)
            try:
                encoded = json.dumps(args, allow_nan=False).encode("utf-8")
            except (TypeError, ValueError):
                raise ValidationError("Arguments must contain finite JSON values") from None
            if len(encoded) > MAX_INPUT_BYTES:
                raise ValidationError("Arguments exceed the 2 MiB limit")
            opts = dict(args)
            if suffix == "record_validations":
                opts["user_authorized"] = False
            result = getattr(get_service(), _METHODS.get(suffix, suffix))(**opts)
            return encode_result(result, args=args)
        except Exception as exc:
            return json.dumps(error_envelope(exc))

    return handler
