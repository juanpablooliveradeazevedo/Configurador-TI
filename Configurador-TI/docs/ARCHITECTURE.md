# Arquitetura

## Objetivo

O Configurador TI reúne ferramentas locais de suporte e administração Windows em uma interface única e adiciona, em sua fase 2B, componentes de QA para gerenciamento de endpoints.

A arquitetura atual separa responsabilidades em quatro blocos.

## 1. Technician Desktop

Interface desktop principal em PyQt6.

Responsabilidades:

- diagnóstico e inventário local;
- rede, DNS e armazenamento;
- monitoramento e observabilidade;
- postura do endpoint;
- auditoria, Timeline e investigação;
- Assistente Técnico;
- ações locais controladas;
- apresentação de status e metadata da build.

Entradas principais:

- `main_gui.py`
- `main_gui.pyw`
- `core_logic.py`
- módulos `*_gui.py` e fundações locais.

## 2. Agent

Processo headless responsável por representar o endpoint no fluxo Fleet.

Características:

- conexão iniciada pelo próprio Agent;
- identidade persistente;
- journal local;
- catálogo remoto fechado;
- modo foreground e adaptação para serviço Windows;
- sem shell remoto livre ou upload/execute arbitrário.

Arquivos principais:

- `agent/`
- `agent_entry.py`

## 3. Backend / Control Plane

Referência local de autoridade para QA.

Responsabilidades:

- identidade;
- tenants e usuários de QA;
- licenciamento/entitlements;
- enrollment;
- endpoints;
- comandos permitidos;
- auditoria e estado Fleet.

A referência atual foi desenhada para bind local e não deve ser interpretada como backend de produção.

Arquivos principais:

- `control_plane/`
- `licensing/`
- `fleet_protocol/`

## 4. Central Web

Interface web de QA que consome o backend.

Responsabilidades:

- sessão;
- navegação administrativa;
- gerenciamento dos objetos de QA;
- visualização de endpoints e resultados;
- preparação de ações allowlisted.

Arquivos principais:

- `central_web/`

## Fluxo simplificado

```text
Technician Desktop
        │
        ├──────────────► recursos locais do Windows
        │
        └──────────────► identidade/licenciamento local
                              │
                              ▼
                       Control Plane
                         ▲         ▲
                         │         │
                    Central Web   Agent
```

## Persistência

O projeto cria estado apenas quando necessário. Arquivos de dados, logs, relatórios,
coletas, bancos locais e identidades não devem ser versionados no Git.

O `.gitignore` público cobre os principais artefatos de runtime e QA.

## Build

O Technician usa PyInstaller como backend oficial de empacotamento.

O perfil portátil preserva:

- `--onefile`;
- `--noconsole`;
- `style.qss`;
- `licensing_public.json`;
- manifesto;
- checksums.

O Agent possui fluxo de build separado para QA.

## Decisões de segurança

- ações remotas são allowlisted;
- não há comando PowerShell remoto livre;
- não há upload/execute genérico;
- alterações transacionais exigem preparação/confirmação;
- provas e rollback são preservados quando aplicáveis;
- coleta remota é mínima;
- estados críticos falham de forma conservadora.

Consulte também [`SECURITY.md`](SECURITY.md).
