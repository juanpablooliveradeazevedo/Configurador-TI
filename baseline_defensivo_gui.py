"""Painel temporal independente da lista/classificação/triagem ativas."""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QWidget,QVBoxLayout,QLabel,QPushButton,QComboBox,
                            QLineEdit,QTextEdit,QTableWidgetItem,QHeaderView,
                            QAbstractItemView,QMessageBox)
from ui_components import FlowRow,UxTable
from operational_ui import local_timestamp,CollapsibleSection
from baseline_defensivo import (BaselineStore,BaselineError,FIELDS,STATES,
                                can_reference,prepare,compare,coverage_summary,coverage_details,unknown_coverage)
from audit_timeline import new_operation_id
from change_intelligence import persist_comparison_safe

LABELS={'TamanhoBytes':'Tamanho (bytes)','ModificadoUtc':'Modificação (UTC)',
        'CriadoUtc':'Criação (UTC)','NomeTecnico':'Nome técnico','ContextoUsuario':'Contexto do usuário',
        'CaminhoTarefa':'Pasta da tarefa','ArquivoStartup':'Arquivo Startup'}


class BaselinePanel(QWidget):
    def __init__(self,host,core):
        super().__init__(host)
        self.host=host;self.core=core
        self.store=BaselineStore(core.DIRETORIO_BASE,host._revisoes_tecnicas.escopo,
                                 core.ModuloSistema._sanitizar_comando_analise_defensiva,core.logger)
        self.result=None;self.generation=0;self.pending=False;self.busy=False
        self.loaded=None;self.rows=[];self.search_cache=[];self.current_coverage=None
        self.last_change_operation_id=None
        layout=QVBoxLayout(self);layout.setContentsMargins(0,8,0,8)
        self.summary=QLabel('Baseline: ainda não carregado. Faça uma análise ou clique em Recarregar.')
        self.summary.setWordWrap(True);self.summary.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.summary)
        self.coverage_line=QLabel('Cobertura atual: aguarde uma análise concluída.')
        self.coverage_line.setWordWrap(True);self.coverage_line.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.coverage_line)
        self.coverage_text=QTextEdit();self.coverage_text.setReadOnly(True)
        self.coverage_text.setMinimumHeight(170);self.coverage_text.setMaximumHeight(230)
        self.coverage_section=CollapsibleSection('Ver cobertura por fonte — atual e baseline',self.coverage_text)
        layout.addWidget(self.coverage_section)
        caution=QLabel('Referência temporal, não whitelist. Novo não implica ameaça; sem alteração não comprova legitimidade.')
        caution.setWordWrap(True);layout.addWidget(caution)
        actions=FlowRow()
        self.save_button=QPushButton('Criar baseline desta análise');self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_reference);actions.addWidget(self.save_button)
        self.reload_button=QPushButton('Recarregar comparação');self.reload_button.clicked.connect(self.refresh);actions.addWidget(self.reload_button)
        self.cancel_button=QPushButton('Cancelar comparação');self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel);actions.addWidget(self.cancel_button)
        layout.addLayout(actions)
        self.counts=QLabel('Novo: — | Alterado: — | Ausente: — | Sem alteração: — | Indeterminado: —')
        self.counts.setWordWrap(True);layout.addWidget(self.counts)
        self.change_summary=QLabel('Change Intelligence: aguarde uma comparação concluída.')
        self.change_summary.setWordWrap(True);self.change_summary.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.change_summary)
        self.investigation_button=QPushButton('Ver na investigação')
        self.investigation_button.setEnabled(False)
        self.investigation_button.clicked.connect(self.open_investigation)
        layout.addWidget(self.investigation_button,alignment=Qt.AlignmentFlag.AlignLeft)
        filters=FlowRow();self.filter=QComboBox();self.filter.addItems(['Somente mudanças','Todos',*STATES])
        self.filter.setToolTip('Somente mudanças inclui Indeterminados. Filtros da análise ativa permanecem independentes.')
        self.filter.currentTextChanged.connect(self.filter_rows);filters.addWidget(self.filter)
        self.search=QLineEdit();self.search.setPlaceholderText('Buscar nas mudanças...')
        self.search.textChanged.connect(self.filter_rows);filters.addWidget(self.search,1)
        layout.addLayout(filters)
        self.matches=QLabel("Nenhuma comparação carregada.");layout.addWidget(self.matches)
        self.table=UxTable(0,4);self.table.setHorizontalHeaderLabels(['Comparação','Tipo','Nome','Resumo da diferença'])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setWordWrap(False);self.table.setMinimumHeight(170);self.table.setMaximumHeight(280)
        header=self.table.horizontalHeader();header.setMinimumSectionSize(85)
        for col,width in ((0,130),(1,145),(2,190)):
            header.setSectionResizeMode(col,QHeaderView.ResizeMode.Interactive);header.resizeSection(col,width)
        header.setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.show_details);layout.addWidget(self.table)
        self.details=QTextEdit();self.details.setReadOnly(True);self.details.setMinimumHeight(145)
        self.detail_section=CollapsibleSection('Detalhes e evidências da comparação',self.details)
        layout.addWidget(self.detail_section)
        self.current_button=QPushButton('Localizar item na análise atual');self.current_button.setEnabled(False)
        self.current_button.clicked.connect(self.locate_current);layout.addWidget(self.current_button)
        self.filter_rows()

    def invalidate(self):
        self.generation+=1;self.result=None;self.pending=False;self.current_coverage=None
        self.coverage_line.setText('Cobertura atual: aguarde uma análise concluída.')
        self.coverage_text.clear();self.coverage_line.setToolTip('');self.coverage_section.set_expanded(False)
        self.rows=[];self.search_cache=[];self.table.setRowCount(0);self.details.clear()
        self.current_button.setEnabled(False);self.save_button.setEnabled(False)
        self.last_change_operation_id=None;self.investigation_button.setEnabled(False)
        self.change_summary.setText('Change Intelligence: comparação suspensa até uma nova análise concluída.')
        self.counts.setText('Comparação suspensa até uma nova análise concluída.')
        self.summary.setText('Baseline preservado. Comparação suspensa até uma análise concluída.')
        self.filter_rows()
        self.cancel()

    def receive(self,result):
        self.generation+=1
        # Whitelist copiada: nunca transportar ComandoOriginal/triagem para o Worker novo.
        errors=result.get('FontesIndisponiveis')
        # Códigos limitados; detalhes arbitrários não são persistidos nem exibidos.
        errors=list(errors) if type(errors) is list and len(errors)<=64 and all(type(e) is str and len(e)<=256 for e in errors) else None
        defender=result.get('Defender');context=result.get('Contexto')
        self.current_coverage=None
        self.result={'Sucesso':result.get('Sucesso'),'Cancelada':result.get('Cancelada'),
                     'FontesIndisponiveis':errors,
                     'Defender':{'Disponivel':defender.get('Disponivel') if type(defender) is dict else None},
                     'Contexto':{field:'informada' if type(context) is dict and type(context.get(field)) is str and context[field].strip() else None for field in ('StartupUser','StartupCommon')},
                     'Itens':[{key:item.get(key) for key in FIELDS} if type(item) is dict else None for item in result['Itens']]}
        self.refresh()

    def cancel(self):
        worker=self.host._operation_workers.get('baseline_defensivo')
        if worker is not None:worker.requestInterruption()

    def refresh(self,_checked=False,write=False):
        if self.host._closing:return
        if self.busy:
            self.pending=True;self.cancel();return
        self.busy=True;self.pending=False;generation=self.generation
        result=self.result;loaded=self.loaded
        operation_id=new_operation_id()
        self.save_button.setEnabled(False);self.reload_button.setEnabled(False);self.cancel_button.setEnabled(True)
        def operation(cancel_callback=None):
            try:
                prepared=prepare(result,self.store.sanitize,cancel_callback) if result is not None else None
                if write:
                    info=self.store.save(prepared,loaded['token'],explicit=True,
                                         replace=loaded['reference'] is not None,cancel_callback=cancel_callback)
                else:info=self.store.load()
                comparison=compare(info['reference'],prepared,cancel_callback) if info['reference'] is not None and prepared is not None else None
                change=None
                if comparison is not None:
                    change=persist_comparison_safe(
                        self.host._get_change_store(),self.host._get_audit_store(),
                        comparison=comparison,reference=info['reference'],current=prepared,
                        operation_id=operation_id,baseline_id=self.store.scope,
                        logger=self.core.logger)
                return {'info':info,'comparison':comparison,
                        'coverage':prepared['coverage'] if prepared is not None else None,
                        'change_intelligence':change}
            except BaselineError as exc:return {'error':str(exc)}
        def done(payload):
            if generation!=self.generation or self.host._closing:return
            self.present(payload)
        def finished(state):
            self.busy=False
            if self.host._closing:return
            self.reload_button.setEnabled(True);self.cancel_button.setEnabled(False)
            if self.pending:self.refresh();return
            self.update_actions()
            if state=='cancelled':
                self.save_button.setEnabled(False)
                self.summary.setText('Operação de baseline cancelada. Recarregue para confirmar o estado em disco.')
        self.host._run(operation,label='Comparação temporal defensiva',operation_key='baseline_defensivo',
                       blocks_navigation=False,on_done=done,on_finally=finished,silent_if_busy=True,
                       audit_source='Baseline defensivo',audit_category='BASELINE',
                       audit_summary=('Criação/substituição e análise de baseline' if write else 'Carregamento e análise de baseline'),
                       audit_details={'action':'CREATE_OR_REPLACE' if write else 'LOAD_AND_ANALYZE'},
                       audit_operation_id=operation_id)

    def update_actions(self):
        self.save_button.setEnabled(not self.busy and self.loaded is not None and self.current_coverage is not None and can_reference(self.result))
        exists=self.loaded is not None and self.loaded.get('reference') is not None
        self.save_button.setText('Atualizar/Substituir baseline...' if exists else 'Criar baseline desta análise')

    def save_reference(self,_checked=False):
        if self.busy or self.loaded is None or self.current_coverage is None or not can_reference(self.result):return
        reference=self.loaded['reference'];generation=self.generation
        if reference:
            text=f"Substituir a referência atual de {local_timestamp(reference['updated'])[0]}, com {len(reference['records'])} itens?"
        else:
            text='Criar uma referência temporal desta análise?'
            if self.loaded['state']=='incompatível':text+=' Baselines de outros escopos serão preservados.'
        affected=[f"{name}: {entry['state']}" for name,entry in self.current_coverage['sources'].items() if entry['state']!='Disponível']
        if affected:
            text+=f'\nEsta análise possui cobertura parcial em {len(affected)} fonte(s):\n'+ '; '.join(affected)
            text+='\nO baseline poderá ser criado, mas itens dependentes dessas fontes poderão ser Indeterminados em comparações futuras. A comparação será conservadora.\nDeseja continuar?'
        else:text+='\nA coleta não reportou falhas nas fontes avaliadas. Metadados individuais ainda podem estar incompletos.'
        text+='\nIsso não aprova itens nem altera classificação ou triagem.'
        answer=QMessageBox.question(self,'Baseline defensivo',text,QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
        if answer!=QMessageBox.StandardButton.Yes or generation!=self.generation or self.busy:return
        self.refresh(write=True)

    def present(self,payload):
        self.current_button.setEnabled(False);self.details.clear();self.detail_section.set_expanded(False);self.rows=[];self.search_cache=[]
        self.last_change_operation_id=None;self.investigation_button.setEnabled(False)
        if 'error' in payload:
            self.current_coverage=None;self.coverage_line.setText('Cobertura não disponível nesta operação.');self.coverage_line.setToolTip('');self.coverage_text.clear()
            self.loaded=None;self.summary.setText('Baseline: erro — '+payload['error']);self.counts.setText('Comparação bloqueada; arquivo preservado.')
            self.change_summary.setText('Change Intelligence não recebeu uma comparação válida.')
        else:
            self.loaded=payload['info'];reference=self.loaded['reference'];state=self.loaded['state']
            self.current_coverage=payload.get('coverage')
            self.show_coverage(reference)
            text='Baseline: '+(coverage_summary(reference.get('coverage') or unknown_coverage()) if reference else state)
            if reference:
                text+=f" | criado: {local_timestamp(reference['created'])[0]} | atualizado: {local_timestamp(reference['updated'])[0]} | {len(reference['records'])} itens"
            elif state=='incompatível':text+=' — outra estação/contexto; nenhuma referência aplicada.'
            self.summary.setText(text)
            self.summary.setToolTip(('Criado: '+local_timestamp(reference['created'])[1]+'\nAtualizado: '+local_timestamp(reference['updated'])[1]) if reference else '')
            comparison=payload['comparison']
            if comparison is not None:
                self.rows=comparison['rows'];self.counts.setText(' | '.join(f'{s}: {comparison["counts"][s]}' for s in STATES))
            else:self.counts.setText('Sem comparação: obtenha uma análise e uma referência deste escopo.')
            change=payload.get('change_intelligence')
            if change is not None:
                self.change_summary.setText(change['summary'])
                if change.get('persisted'):
                    self.last_change_operation_id=change.get('operation_id')
                    self.investigation_button.setEnabled(bool(self.last_change_operation_id))
            else:
                self.change_summary.setText('Change Intelligence: não há comparação entre dois estados nesta operação.')
        self.table.setUpdatesEnabled(False);self.table.blockSignals(True)
        try:
            self.table.setRowCount(len(self.rows))
            for i,row in enumerate(self.rows):
                e=row['after'] or row['before']
                summary=', '.join(LABELS.get(field,field) for field,_,_ in row['changes']) or row['reason']
                values=(row['state'],e['Tipo'] or '—',e['Nome'] or '—',summary)
                self.search_cache.append(' '.join(str(v or '') for v in [*values,*e.values()]).casefold())
                for col,value in enumerate(values):
                    cell=QTableWidgetItem(value);cell.setToolTip(value);self.table.setItem(i,col,cell)
        finally:self.table.blockSignals(False);self.table.setUpdatesEnabled(True)
        self.filter_rows();self.update_actions()

    def show_coverage(self,reference):
        coverage=self.current_coverage
        lines=[]
        if coverage is not None:
            affected=[f"{name}: {entry['state']}" for name,entry in coverage['sources'].items() if entry['state']!='Disponível']
            self.coverage_line.setText('Coleta atual: '+coverage_summary(coverage)+(' | '+ '; '.join(affected) if affected else ''))
            self.coverage_line.setToolTip(coverage_details(coverage))
            lines+=['COLETA ATUAL',coverage_details(coverage),'']
        else:
            self.coverage_line.setText('Cobertura atual: aguarde uma análise concluída.')
            self.coverage_line.setToolTip('')
        if reference is not None:
            lines+=['BASELINE',coverage_details(reference.get('coverage') or unknown_coverage()),'']
        lines+=['Disponível significa sem falha reportada pelo coletor existente; não garante metadados individuais completos.',
                'Novo exige cobertura da referência. Ausente exige cobertura atual. Pares observados mantêm comparação direta.',
                'Registro agrega as visões 32/64-bit por escopo/tipo. Arquivos associados herdam a fonte de origem.',
                'Classificação de item “Não disponível” não determina cobertura de fonte.']
        self.coverage_text.setPlainText('\n'.join(lines))


    def filter_rows(self,_value=None):
        mode=self.filter.currentText();query=self.search.text().strip().casefold();visible=0
        for index,row in enumerate(self.rows):
            show=(mode=='Todos' or (mode=='Somente mudanças' and row['state']!='Sem alteração') or row['state']==mode) and query in self.search_cache[index]
            self.table.setRowHidden(index,not show)
            visible+=int(show)
        self.matches.setText(f"Registros neste filtro: {visible}. Duplicatas não pareadas podem representar os dois lados.")
        self.table.setVisible(bool(visible));self.detail_section.setVisible(bool(visible));self.current_button.setVisible(bool(visible))
        current=self.table.currentRow()
        if current>=0 and self.table.isRowHidden(current):self.table.clearSelection();self.details.clear();self.current_button.setEnabled(False)

    def selected(self):
        i=self.table.currentRow()
        return self.rows[i] if 0<=i<len(self.rows) and not self.table.isRowHidden(i) and self.table.selectionModel().hasSelection() else None

    def show_details(self):
        row=self.selected();self.current_button.setEnabled(row is not None and row['index'] is not None and self.result is not None)
        if row is None:self.details.clear();return
        lines=[row['state'],row['reason'],'Referência temporal não substitui classificação automática nem revisão humana.']
        lines += [f'{LABELS.get(field,field)}: {before} → {after}' for field,before,after in row['changes']]
        for title,evidence in (('Snapshot da referência',row['before']),('Evidências atuais',row['after'])):
            if evidence is not None:
                lines+=['',title]+[f'{field}: {value}' for field,value in evidence.items() if value is not None]
        self.details.setPlainText('\n'.join(lines))
        self.detail_section.set_expanded(True)

    def locate_current(self,_checked=False):
        row=self.selected()
        if row is None or row['index'] is None or self.result is None:return
        index=row['index'];table=self.host.tabela_analise_defensiva
        if index>=table.rowCount():return
        if table.isRowHidden(index):
            self.details.append('O item atual está oculto pelos filtros da análise. Ajuste-os para localizá-lo.');return
        table.selectRow(index);table.scrollToItem(table.item(index,0));self.host._mostrar_detalhes_analise_defensiva()

    def open_investigation(self,_checked=False):
        if self.last_change_operation_id:
            self.host._abrir_investigacao(self.last_change_operation_id)
