"""Optional infrastructure-as-code scanners."""
from .base import Detector

class TrivyDetector(Detector):
    name='trivy'
    kind='iac'
    def plan(self,target,inventory):
        return {'argv':[self.name,'config','--format','sarif','--skip-check-update',target['root']],'timeout_s':600,'env':{}}

class CheckovDetector(Detector):
    name='checkov'
    kind='iac'
    findings_exit_codes={0,1}
    def plan(self,target,inventory):
        return {'argv':[self.name,'-d',target['root'],'-o','sarif','--skip-download','--skip-framework','terraform_plan'],'timeout_s':600,'env':{}}
