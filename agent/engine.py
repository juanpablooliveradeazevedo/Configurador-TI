"""Adapter to the existing Safe Playbook/Transactional Action engine."""
import platform
from assist import AssistStore
from monitoring_foundation import MonitoringService
from licensing.contracts import Denied
from licensing.runtime import execution_gate
from fleet_protocol.contracts import action,proof

class VerifiedGate:
    def __init__(self,entitlement,clock): self.entitlement,self.clock=entitlement,clock
    def require(self,feature):
        p=self.entitlement
        if self.clock()>=min(p['expires_at'],p['offline_until']) or feature not in p['features']: raise Denied('FEATURE_DENIED')

class AgentActionEngine:
    def __init__(self,root):
        self.store=AssistStore(root);self.monitor=MonitoringService(self.store)
        config=self.store.get_monitoring_configuration()
        self.monitor.interval_seconds=config['interval_seconds'];self.monitor.retention_days=config['retention_days']
    def summary(self):
        system=platform.system();machine=platform.machine().lower()
        snapshot=self.store.get_latest_snapshot()
        posture={'assessment':'NOT_COLLECTED','checks':0}
        if snapshot:
            checks=snapshot['checks'];assessments={c['assessment'] for c in checks}
            posture={'assessment':'ATTENTION' if 'ATTENTION' in assessments else 'OK' if len(checks)==6 and assessments=={'OK'} else 'INDETERMINATE','checks':min(len(checks),6)}
        return {'inventory':{'os':system if system in ('Windows','Linux','Darwin') else 'Other','architecture':'x64' if machine in ('amd64','x86_64') else 'arm64' if machine in ('aarch64','arm64') else 'Other'},'posture':posture,'monitoring':{'interval_seconds':self.monitor.interval_seconds,'retention_days':self.monitor.retention_days,'state':self.monitor.status}}
    def prepare(self,c,gate):
        if self.store.list_action_runs(limit=1,offset=1999): raise Denied('HISTORY_CAPACITY_REACHED')
        spec=action(c['action_id'],c['parameters']);definition=self.store.action_definition(c['action_id'])
        if definition.requires_elevation or definition.side_effect_class!='LOCAL_REVERSIBLE_CHANGE': raise Denied('PRIVILEGE_DENIED')
        with execution_gate(gate):
            context=self.store.create_context('MONITORING_SETTINGS',source_id=c['command_id'],summary='Operação remota autorizada',monitoring_state=self.monitor.status)
            session=self.store.start_session(context['context_id'],spec['playbook_id'],created_by=c['actor'])
            step=next(s for s in session['steps'] if s['definition']['action_ref']==c['action_id'])
            return self.store.prepare_action(session['session_id'],step['step_id'],requested_by=c['actor'],parameters=c['parameters'],monitoring_service=self.monitor)
    def execute(self,run_id,gate,cancel):
        with execution_gate(gate):
            self.store.confirm_action(run_id)
            return self.store.execute_action(run_id,monitoring_service=self.monitor,cancel_callback=cancel)
    def make_proof(self,c,run,started,now,uncertain=False):
        run=run or {};before=run.get('before') or {};after=run.get('actual_after') or {}
        result=run.get('result','INDETERMINATE')
        if result not in ('SUCCESS','FAILURE','INDETERMINATE','CANCELLED','ROLLED_BACK'): result='INDETERMINATE'
        if uncertain: result='INDETERMINATE'
        p={k:c[k] for k in ('command_id','correlation_id','tenant_id','device_id','actor','action_id','playbook_id')}
        p.update(action_run_id=run.get('action_run_id'),before=before.get('old_interval_seconds'),after=after.get('interval_seconds'),dry_run=bool(run.get('dry_run')),preconditions=bool(run.get('preconditions')) and all(x.get('ok') is True for x in run['preconditions']),execution='RECOVERY_REQUIRED' if uncertain else 'EXECUTED' if run.get('started_at') else 'NOT_STARTED',validator=result=='SUCCESS',rollback_available=bool(run.get('rollback_target') and run.get('started_at') and run.get('status') in ('SUCCEEDED','ROLLBACK_READY','RECOVERY_REQUIRED','ROLLBACK_FAILED','FAILED')),result=result,started_at=started,completed_at=max(started,now))
        return proof(p)
