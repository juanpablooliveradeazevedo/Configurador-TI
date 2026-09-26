"""Qt/engine tests: executor rechecks, degraded reads, worker and close lifecycle."""
import unittest
from unittest.mock import patch,Mock
import test_ux_global as base
import test_licensing_2a as fixtures
import test_transactional_action_engine_1de_c as tx
from licensing import runtime
from licensing.gui import AccountDialog
from licensing.contracts import Denied
from endpoint_posture import EndpointPostureService
class ExecutionGateTests(fixtures.Fixture):
    def setUp(self):
        super().setUp();self.tx=tx.TransactionalActionEngineTests();self.tx.setUp();self.addCleanup(self.tx.doCleanups)
    def test_expiry_after_confirmation_denies_executor_without_mutation(self):
        self.login();run=self.tx.prepare();self.tx.store.confirm_action(run['action_run_id']);self.clock.now+=86401
        with patch.object(runtime,'_runtime',self.client):
            with self.assertRaises(Denied):self.tx.store.execute_action(run['action_run_id'],monitoring_service=self.tx.service)
        self.assertEqual(self.tx.store.get_monitoring_configuration()['interval_seconds'],60);self.assertEqual(self.tx.store.get_action_run(run['action_run_id'])['status'],'READY')
    def test_rollback_and_recovery_available_after_expiry(self):
        self.login()
        with patch.object(runtime,'_runtime',self.client):
            run=self.tx.execute();self.clock.now+=86401;self.tx.store.rollback_action(run['action_run_id'],monitoring_service=self.tx.service)
        self.assertEqual(self.tx.store.get_monitoring_configuration()['interval_seconds'],60)
    def test_posture_denial_prevents_collector_call(self):
        collector=Mock();store=Mock()
        with patch.object(runtime,'_runtime',self.client):
            with self.assertRaises(Denied):EndpointPostureService(store,collector).collect_once()
        collector.collect_all.assert_not_called();store.record_snapshot.assert_not_called()
    def test_playbook_denied_but_history_readable(self):
        with patch.object(runtime,'_runtime',self.client):
            with self.assertRaises(Denied):self.tx.store.start_session(self.tx.session['context_id'],'MONITORING_ALERT_REVIEW')
            self.assertTrue(self.tx.store.get_session_details(self.tx.session['session_id']))
class LicensingQtTests(unittest.TestCase):
    def setUp(self):self.case=base.UxTests();self.case.setUp();self.w=self.case.w
    def tearDown(self):self.case.tearDown()
    def test_account_nonmodal_and_dev_explicit(self):
        with patch.object(self.w,'_run') as run:
            self.w._open_licensing_account();d=self.w._account_dialog
            self.assertFalse(d.isModal());self.assertIn('DEV_UNMANAGED',d.status.text());self.assertFalse(d.login_button.isEnabled());self.assertNotIn('access_token',d.details.toPlainText());run.assert_not_called()
    def test_periodic_network_uses_nonoverlapping_worker(self):
        with patch.object(self.w,'_run') as run:
            self.w._licensing_tick();self.assertEqual(run.call_args.kwargs['operation_key'],'licensing_account');self.assertFalse(run.call_args.kwargs['blocks_navigation'])
    def test_login_code_hidden_and_absent_from_worker_args(self):
        gate=Mock(dev=False);gate.snapshot.return_value={'state':'AUTH_REQUIRED','features':[],'degraded':True};d=AccountDialog(self.w,gate);d.code.setText('one-use-fixture')
        with patch.object(self.w,'_run') as run:
            d.login();self.assertEqual(d.code.text(),'');self.assertNotIn('one-use-fixture',str(run.call_args.kwargs));run.call_args.args[0]();gate.login.assert_called_once_with('one-use-fixture')
    def test_denied_ui_avoids_confirmation_popups(self):
        gate=Mock();gate.is_allowed.return_value=False;gate.explain.return_value='Requer licença válida'
        with patch.object(runtime,'_runtime',gate),patch.object(base.gui.QMessageBox,'question') as modal:
            self.w.assist_panel.start_selected_playbook();self.w.assist_panel.execute_prepared_action();self.w.endpoint_posture_panel.collect();modal.assert_not_called()
            self.assertIn('Requer',self.w.assist_panel.action_dry_run.text());self.assertIn('Requer',self.w.endpoint_posture_panel.notice.text())
    def test_logout_warning_survives_final_snapshot(self):
        gate=Mock(dev=False);state={'state':'AUTH_REQUIRED','features':[],'degraded':True};gate.snapshot.return_value=state;d=AccountDialog(self.w,gate)
        d.render(dict(state,remote_logout=False));d.render(state);self.assertIn('Revogação remota não confirmada',d.details.toPlainText())
    def test_close_waits_without_blocking_gui(self):
        from PyQt6.QtGui import QCloseEvent
        worker=Mock(_operation_key='licensing_account');worker.isRunning.return_value=True;self.w._workers.append(worker)
        try:
            with patch.object(base.gui.QMessageBox,'warning',return_value=base.gui.QMessageBox.StandardButton.Yes) as warning,patch.object(base.gui.QTimer,'singleShot') as schedule:
                event=QCloseEvent();self.w.closeEvent(event);self.assertFalse(event.isAccepted());worker.wait.assert_not_called();self.assertEqual(schedule.call_args.args[0],100)
                worker.isRunning.return_value=False;event=QCloseEvent();self.w.closeEvent(event);self.assertTrue(event.isAccepted());warning.assert_called_once()
        finally:
            self.w._workers.remove(worker)
            if worker in base.gui.WORKERS_EM_ENCERRAMENTO:base.gui.WORKERS_EM_ENCERRAMENTO.remove(worker)
if __name__=='__main__':unittest.main(verbosity=2)
