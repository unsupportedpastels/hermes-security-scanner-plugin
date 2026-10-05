"""Semgrep adapter; no implicit remote ruleset or installation."""
from pathlib import Path
from .base import Detector

class SemgrepDetector(Detector):
    name='semgrep'
    findings_exit_codes={0,1}

    def plan(self,target,inventory):
        config=self.options.get('rules_path') or self.options.get('config')
        if not config:
            return {'argv':[],'timeout_s':600,'env':{},'status':'unavailable','reason':'no offline ruleset configured'}
        if not self.options.get('config') and not Path(config).exists():
            return {'argv':[],'timeout_s':600,'env':{},'status':'unavailable','reason':'no offline ruleset configured'}
        return {'argv':[self.name,'scan','--sarif','--metrics=off','--disable-version-check','--config',str(config),target['root']], 'timeout_s':600,'env':{}}
