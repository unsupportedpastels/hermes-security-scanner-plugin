"""Host-authenticated, profile-local workbench API with explicit user consent.

Hermes imports this file standalone and supplies /api/plugins/hermes-security.
Load only our sibling package by path; never depend on cwd or mutate sys.path.
"""
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import threading

from fastapi import APIRouter, Body, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute

_PACKAGE_PATH = Path(__file__).resolve().parents[1] / 'hermes_security'
_PACKAGE_NAME = '_hermes_security_dashboard_' + hashlib.sha256(str(_PACKAGE_PATH).encode()).hexdigest()[:16]
if _PACKAGE_NAME not in sys.modules:
    _spec = importlib.util.spec_from_file_location(_PACKAGE_NAME, _PACKAGE_PATH / '__init__.py', submodule_search_locations=[str(_PACKAGE_PATH)])
    if _spec is None or _spec.loader is None:
        raise ImportError('Security package unavailable')
    _package = importlib.util.module_from_spec(_spec)
    sys.modules[_PACKAGE_NAME] = _package
    try:
        _spec.loader.exec_module(_package)
    except Exception:
        sys.modules.pop(_PACKAGE_NAME, None)
        raise
SecurityService = importlib.import_module('.service', _PACKAGE_NAME).SecurityService
resolve_data_dir = importlib.import_module('.config', _PACKAGE_NAME).resolve_data_dir
SecurityError = importlib.import_module('.errors', _PACKAGE_NAME).SecurityError
ValidationError = importlib.import_module('.errors', _PACKAGE_NAME).ValidationError

_services = {}
_services_lock = threading.Lock()
MAX_JSON_BYTES = 2 * 1024 * 1024
_ERRORS = {
    'invalid_input': (400, 'Invalid request.'),
    'not_found': (404, 'Requested record was not found.'),
    'conflict': (409, 'The current record state does not permit this action.'),
    'sealed': (409, 'This scan is sealed.'),
    'policy_denied': (403, 'This action is not authorized by the safety policy.'),
}


def get_service():
    """Resolve on every request: a cached service must not cross profile homes."""
    directory = resolve_data_dir().resolve()
    with _services_lock:
        if directory not in _services:
            home = directory.parent.parent
            profile = home.name if home.parent.name == 'profiles' else 'default'
            _services[directory] = SecurityService(directory, profile=profile)
        return _services[directory]


def _error(code):
    status, message = _ERRORS.get(code, (500, 'Security service request failed.'))
    return JSONResponse({'error': {'code': code if code in _ERRORS else 'internal_error', 'message': message}}, status_code=status)


class SecurityRoute(APIRoute):
    """Bound JSON and sanitize errors without modifying the host's handlers."""
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def safe_handler(request):
            try:
                if request.method == 'POST':
                    body = bytearray()
                    async for chunk in request.stream():
                        body.extend(chunk)
                        if len(body) > MAX_JSON_BYTES:
                            return _error('invalid_input')
                    request._body = bytes(body)
                response = await handler(request)
                if response.media_type == 'application/json' and len(response.body) > MAX_JSON_BYTES:
                    return _error('internal_error')
                return response
            except RequestValidationError:
                return _error('invalid_input')
            except SecurityError as exc:
                return _error(exc.code)
            except Exception:
                return _error('internal_error')
        return safe_handler


router = APIRouter(route_class=SecurityRoute)


def _broadcast(event, payload):
    try:
        from hermes_cli.plugin_events import broadcast_plugin_event
        broadcast_plugin_event('hermes-security', event, payload)
    except Exception:
        pass  # Optional delivery must never roll back an accepted action.


@router.get('/health')
def health():
    return {'ok': True, 'plugin': 'hermes-security'}


@router.get('/summary')
def summary():
    return get_service().summary()


@router.get('/scans')
def scans(q: str | None = None, status: str | None = None, mode: str | None = None,
          limit: int = Query(50, ge=0, le=100), offset: int = Query(0, ge=0)):
    return get_service().workbench_scans(q=q, status=status, mode=mode, limit=limit, offset=offset)


@router.post('/scans')
def start_scan(body: dict = Body(...)):
    service = get_service()
    opts = dict(body)
    if 'safetyLevel' in opts:
        if 'safety_level' in opts:
            raise ValidationError('ambiguous safety level')
        opts['safety_level'] = opts.pop('safetyLevel')
    if {'user_authorized', 'authorization_source'} & opts.keys():
        raise ValidationError('authority fields are not request options')
    confirmed = opts.pop('confirm', None)
    authorize = opts.get('safety_level') == 'local-safe' and opts.get('allowLocalValidation') is True
    if authorize and confirmed != 'local-safe':
        return _consent_error()
    created = service.start_scan(**opts, user_authorized=authorize,
                                 authorization_source='dashboard' if authorize else None)
    result = service.get_scan(created['scanId'])
    _broadcast('scan.updated', {'scanId': created['scanId']})
    return result


def _consent_error():
    return JSONResponse({'error': {'code': 'invalid_input', 'message': 'Please confirm this action for the selected scan.'}}, status_code=400)


def _level_error(level):
    return JSONResponse({'error': {'code': 'policy_denied', 'message': 'This action requires a scan created for ' + ('testing on this computer.' if level == 'local-safe' else 'testing a running app.')}}, status_code=403)


@router.get('/scans/{scan_id}/grants')
def grants(scan_id: str):
    return get_service().list_grants(scan_id)


@router.post('/scans/{scan_id}/authorize-validation')
def authorize_validation(scan_id: str, body: dict = Body(...)):
    if body.get('confirm') != scan_id:
        return _consent_error()
    service = get_service()
    if service.get_scan(scan_id)['safety_level'] != 'active-authorized':
        return _level_error('active-authorized')
    if set(body) - {'confirm', 'origin', 'minutes', 'maxRequests'}:
        raise ValidationError('unknown authorization option')
    minutes, cap = body.get('minutes', 30), body.get('maxRequests', 20)
    if type(minutes) is not int or not 1 <= minutes <= 240 or type(cap) is not int or not 1 <= cap <= 200:
        raise ValidationError('invalid grant limits')
    # Share CLI origin syntax: do not silently discard paths or credentials.
    commands = importlib.import_module('.commands', _PACKAGE_NAME)
    try:
        origin = commands._origin(body.get('origin'))
    except (ValueError, TypeError, AttributeError, commands.argparse.ArgumentTypeError):
        raise ValidationError('invalid origin') from None
    grant = service.mint_grant(scan_id, origins=[origin], actions=['http-probe'],
                              expires_in_s=minutes * 60, max_requests=cap, created_by='dashboard')
    _broadcast('scan.updated', {'scanId': scan_id})
    return service.store.get_grant(grant['grantId'])


@router.post('/scans/{scan_id}/grants/{grant_id}/revoke')
def revoke_grant(scan_id: str, grant_id: str, body: dict = Body(...)):
    if body.get('confirm') != scan_id:
        return _consent_error()
    if set(body) != {'confirm'}:
        raise ValidationError('invalid revoke options')
    service = get_service()
    if service.store.get_grant(grant_id)['scanId'] != scan_id:
        raise ValidationError('grant does not belong to this scan')
    service.revoke_grant(grant_id)
    _broadcast('scan.updated', {'scanId': scan_id})
    return service.store.get_grant(grant_id)


@router.post('/scans/{scan_id}/run-validation')
def run_validation(scan_id: str, body: dict = Body(...)):
    if body.get('confirm') != scan_id:
        return _consent_error()
    service = get_service()
    if service.get_scan(scan_id)['safety_level'] != 'local-safe':
        return _level_error('local-safe')
    plans = body.get('plans')
    if (set(body) != {'confirm', 'plans'} or not isinstance(plans, list) or not plans or
            any(not isinstance(p, dict) or p.get('kind') != 'local-command' or p.get('level') != 'local-safe' for p in plans)):
        raise ValidationError('requires local-command plans at local-safe level')
    result = service.record_validations(scan_id, plans=plans, user_authorized=True, authorization_source='dashboard')
    recorded = {r['receiptId']: r for r in service.store.validations(scan_id)}
    _broadcast('scan.updated', {'scanId': scan_id})
    return {'scanId': scan_id, 'receipts': [recorded[r['receiptId']] for r in result['receipts']]}


@router.get('/scans/{scan_id}')
def scan(scan_id: str, section: str | None = None,
         limit: int = Query(50, ge=0, le=100), offset: int = Query(0, ge=0)):
    return get_service().get_scan(scan_id, section=section, limit=limit, offset=offset)


@router.post('/scans/{scan_id}/cancel')
def cancel(scan_id: str):
    service = get_service()
    service.cancel(scan_id)
    result = service.get_scan(scan_id)
    _broadcast('scan.updated', {'scanId': scan_id})
    return result


@router.post('/scans/{scan_id}/resume')
def resume(scan_id: str):
    service = get_service()
    service.resume(scan_id)
    result = service.get_scan(scan_id)
    _broadcast('scan.updated', {'scanId': scan_id})
    return result


@router.get('/scans/{scan_id}/activity')
def activity(scan_id: str, after_id: int = Query(0, ge=0), limit: int = Query(200, ge=0, le=500)):
    return get_service().activity(scan_id, after_id=after_id, limit=limit)


@router.get('/scans/{scan_id}/coverage')
def coverage(scan_id: str):
    return get_service().coverage(scan_id)


@router.get('/findings')
def findings(q: str | None = None, status: str | None = None, severity: str | None = None,
             evidenceState: str | None = None, validationLevel: str | None = None,
             repo: str | None = None, owasp: str | None = None, source: str | None = None,
             chained: bool | None = None, limit: int = Query(50, ge=0, le=100), offset: int = Query(0, ge=0)):
    return get_service().workbench_findings(q=q, triage=status, severity=severity,
        evidence_state=evidenceState, validation_level=validationLevel, repo_key=repo,
        owasp=owasp, source=source, chained=chained, limit=limit, offset=offset)


@router.get('/findings/{finding_id}')
def finding(finding_id: str):
    return get_service().get_finding(finding_id)


@router.post('/findings/{finding_id}/triage')
def triage(finding_id: str, body: dict = Body(...)):
    if set(body) - {'state', 'note'} or 'state' not in body:
        raise ValidationError('invalid triage body')
    service = get_service()
    service.triage(finding_id, body['state'], body.get('note'))
    result = service.get_finding(finding_id)
    _broadcast('finding.updated', {'findingId': finding_id})
    return result


@router.get('/findings/{finding_id}/patch')
def patch(finding_id: str):
    return get_service().patch_preview(finding_id)


@router.get('/repositories')
def repositories(limit: int = Query(50, ge=0, le=100), offset: int = Query(0, ge=0)):
    return get_service().list_repositories(limit=limit, offset=offset)


@router.get('/exports/{scan_id}/{format}')
def export(scan_id: str, format: str, download: bool = False):
    if format not in {'md', 'sarif', 'json', 'csv'}:
        raise ValidationError('unsupported export format')
    result = get_service().export(scan_id, format)
    if not download:
        # The desktop SDK transport JSON-parses every body, so Markdown/CSV need an envelope.
        return result
    return Response(result['content'], media_type=result['contentType'],
                    headers={'Content-Disposition': 'attachment; filename="' + result['filename'] + '"'})
