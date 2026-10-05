"""Optional detector registry. Nothing is installed or downloaded implicitly."""
from pathlib import Path
from .base import Detector, DetectorReceipt, safe_run
from .sarif import import_sarif
from .secrets import BuiltinSecretsDetector, GitleaksDetector
from .semgrep import SemgrepDetector
from .dependencies import OSVScannerDetector
from .iac import TrivyDetector, CheckovDetector

REGISTRY={'builtin-secrets':BuiltinSecretsDetector,'semgrep':SemgrepDetector,
          'gitleaks':GitleaksDetector,'osv-scanner':OSVScannerDetector,
          'trivy':TrivyDetector,'checkov':CheckovDetector}


def run_detectors(names,target,inventory,work_dir):
    work=Path(work_dir)
    root=Path(target['root']).resolve()
    if work.resolve()==root or root in work.resolve().parents:
        from hermes_security.errors import ValidationError
        raise ValidationError('detector work directory must be outside target')
    work.mkdir(parents=True,exist_ok=True,mode=0o700)
    candidates=[]; receipts=[]
    for name in names:
        if name not in REGISTRY:
            receipts.append(DetectorReceipt(str(name),status='unavailable',error='unknown detector'))
            continue
        options=target.get('detectorOptions',{}).get(name,{})
        detector=REGISTRY[name](work_dir=work,**options)
        receipts.append(detector.run(target,inventory))
        candidates.extend(detector.candidates)
    return candidates,receipts
