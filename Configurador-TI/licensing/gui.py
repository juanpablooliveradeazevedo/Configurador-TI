"""Nonmodal account UI; secrets/network stay in the existing Worker path."""
from datetime import datetime,timezone
from PyQt6.QtWidgets import QDialog,QVBoxLayout,QLabel,QLineEdit,QPushButton,QPlainTextEdit,QMessageBox
from PyQt6.QtCore import Qt
class AccountDialog(QDialog):
    def __init__(self,host,gate):
        super().__init__(host);self.host,self.gate=host,gate;self.remote_logout_unconfirmed=False
        self.setWindowTitle('Licença & Conta');self.resize(660,540);layout=QVBoxLayout(self)
        self.status=QLabel();self.status.setWordWrap(True);self.status.setTextFormat(Qt.TextFormat.PlainText);layout.addWidget(self.status)
        info=QLabel('Conexão QA: código temporário emitido pelo administrador. OIDC externo requer provider no servidor. Nenhuma senha é salva no Configurador TI.');info.setWordWrap(True);layout.addWidget(info)
        self.code=QLineEdit();self.code.setEchoMode(QLineEdit.EchoMode.Password);self.code.setPlaceholderText('Código QA temporário');layout.addWidget(self.code)
        self.login_button=QPushButton('Login / Conectar');self.renew_button=QPushButton('Reconectar / renovar');self.logout_button=QPushButton('Logout');self.reenroll_button=QPushButton('Reinscrever dispositivo com novo código')
        for b in self.buttons: layout.addWidget(b)
        self.details=QPlainTextEdit();self.details.setReadOnly(True);layout.addWidget(self.details)
        self.login_button.clicked.connect(self.login);self.renew_button.clicked.connect(lambda:self.run(gate.renew));self.logout_button.clicked.connect(lambda:self.run(gate.logout));self.reenroll_button.clicked.connect(self.reenroll)
        self.render(gate.snapshot())
    @property
    def buttons(self): return (self.login_button,self.renew_button,self.logout_button,self.reenroll_button)
    def login(self):
        code=self.code.text();self.code.clear()
        if code: self.run(lambda:self.gate.login(code))
    def reenroll(self):
        if not self.code.text(): self.status.setText('Informe um novo código QA emitido pelo administrador.');return
        if QMessageBox.question(self,'Reinscrever dispositivo','A sessão local será encerrada e uma nova chave criada. O dispositivo antigo continua registrado até revogação administrativa. Continuar?',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes: return
        code=self.code.text();self.code.clear();self.run(lambda:self.gate.reenroll(code))
    def run(self,fn):
        self.remote_logout_unconfirmed=False
        for b in self.buttons: b.setEnabled(False)
        self.host._run(fn,label='Atualizando licença e conta',progress=None,on_done=self.render,operation_key='licensing_account',blocks_navigation=False,silent_if_busy=True,on_finally=lambda _state:self.render(self.gate.snapshot()))
    def render(self,state):
        for b in self.buttons: b.setEnabled(not self.gate.dev)
        self.status.setText('Estado: '+state['state']+' | '+('Online' if state.get('online') else 'Offline / local')+('\nModo degradado: leitura, histórico, exportação e suporte disponíveis.' if state.get('degraded') else ''))
        def date(v): return datetime.fromtimestamp(v,timezone.utc).isoformat() if v else '—'
        lines=['Motivo: '+str(state.get('reason') or '—'),'Tenant: '+str(state.get('tenant') or '—'),'Plano: '+str(state.get('plan') or '—'),'Validade: '+date(state.get('expires_at')),'Lease offline: '+date(state.get('offline_until')),'Dispositivo: '+str(state.get('device_id') or 'não inscrito'),'Sessão: '+str(state.get('session_id') or 'não autenticado'),'Features: '+', '.join(state.get('features',[])),'Suporte: informe estado e IDs; nunca envie tokens, códigos ou state.bin.']
        if self.gate.dev: lines.insert(0,'DESENVOLVIMENTO EXPLÍCITO — somente fonte, sem licença comercial.')
        if 'remote_logout' in state: self.remote_logout_unconfirmed=not state['remote_logout']
        if self.remote_logout_unconfirmed: lines.append('Logout local concluído. Revogação remota não confirmada; solicite force logout ao administrador.')
        self.details.setPlainText('\n'.join(lines));self.host.license_status.setText('Licença: '+state['state'])
