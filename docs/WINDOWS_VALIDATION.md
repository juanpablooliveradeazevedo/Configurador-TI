# Gates nativos Windows

A candidata pública deriva da REBRAND GLOBAL R1. Os testes portáveis foram aprovados,
mas os itens abaixo continuam dependendo de Windows real e revisão humana.

## Technician

- [ ] build PyInstaller;
- [ ] abertura do EXE;
- [ ] `--onefile`;
- [ ] `--noconsole`;
- [ ] carregamento de `style.qss`;
- [ ] caminhos fora de `_MEIPASS`;
- [ ] GUI responsiva;
- [ ] inventário/diagnóstico;
- [ ] Assistente Técnico;
- [ ] Monitoramento;
- [ ] relatórios;
- [ ] persistência local;
- [ ] comportamento em usuário padrão e elevação sob demanda.

## Agent

- [ ] build do EXE;
- [ ] smoke headless;
- [ ] instalação explícita do serviço;
- [ ] conta LocalService;
- [ ] start manual;
- [ ] ACL em `%ProgramData%\ConfiguradorTI-Agent`;
- [ ] bootstrap protegido;
- [ ] DPAPI;
- [ ] enrollment;
- [ ] stop/start/restart;
- [ ] identidade persistente;
- [ ] revogação e reenrollment.

## Central / Backend

- [ ] iniciar ambiente QA isolado;
- [ ] login em navegador real;
- [ ] sessão/CSRF/origin/Host;
- [ ] criação de tenant/usuário/licença;
- [ ] enrollment;
- [ ] visualização de endpoint;
- [ ] preparação e envio de ação allowlisted;
- [ ] proof of work.

## Distribuição

- [ ] gerar pasta final e ZIP portátil;
- [ ] validar manifesto;
- [ ] validar SHA-256;
- [ ] validar integridade do ZIP;
- [ ] confirmar ausência de fontes/estado privado no pacote final;
- [ ] scanner de branding no artefato final.

Nenhum desses itens deve ser marcado como concluído apenas porque a suíte portável passou.
