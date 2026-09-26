# Configurador TI 🖥️

Aplicação desktop em desenvolvimento para **diagnóstico, inventário, manutenção, monitoramento, automação e apoio à administração de computadores Windows**.

> **Status:** desenvolvimento ativo / candidata de QA.  
> **Base pública:** derivada da candidata **REBRAND GLOBAL R1 (2026-09-25)**.  
> **Regressão da candidata-base:** 844 testes — 841 aprovados, 3 ignorados por dependência de ambiente/plataforma e 0 falhas.  
> **Validações nativas Windows:** ainda pendentes antes de qualquer promoção para produção.

## Visão geral

O Configurador TI nasceu da observação de rotinas recorrentes de suporte técnico e da ideia de reunir, em uma única interface, informações e ferramentas que normalmente ficam distribuídas entre diferentes utilitários, comandos e telas do Windows.

O projeto é desenvolvido como iniciativa pessoal de estudo e evolução prática em desenvolvimento de software, automação, Windows, redes, segurança e qualidade de software.

Entre os recursos atualmente implementados estão:

- diagnóstico do computador e inventário de hardware/sistema;
- rede, DNS e informações de conectividade;
- discos, S.M.A.R.T. e armazenamento;
- sensores e monitoramento local;
- análise defensiva e postura do endpoint;
- logs, auditoria, Timeline e investigação;
- Assistente Técnico com playbooks guiados e ações controladas;
- motor transacional com confirmação, validação e rollback;
- Agent headless, Central Web e backend/API de referência para QA;
- empacotamento com PyInstaller e validações de distribuição.

## Arquitetura

A candidata atual possui quatro componentes principais:

```text
┌────────────────────────────┐
│ Technician Desktop (PyQt6) │
└─────────────┬──────────────┘
              │
              │ recursos locais / licenciamento
              ▼
┌────────────────────────────┐
│ Backend / Control Plane    │
└─────────────┬──────────────┘
              │ API local de QA
       ┌──────┴──────┐
       ▼             ▼
┌──────────────┐  ┌──────────────┐
│ Central Web  │  │ Agent        │
│ interface QA │  │ headless     │
└──────────────┘  └──────────────┘
```

Mais detalhes em [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Tecnologias

- Python
- PyQt6
- PowerShell
- WMI / CIM
- SQLite
- `cryptography`
- PyInstaller
- Git
- APIs e ferramentas nativas do Windows

## Estrutura do repositório

```text
Configurador-TI/
├── main_gui.py / main_gui.pyw    # interface e launcher gráfico
├── core_logic.py                 # lógica local principal
├── agent/                        # Agent headless / serviço Windows
├── central_web/                  # Central Web de QA
├── control_plane/                # backend e autoridade local de QA
├── fleet_protocol/               # contratos e transporte
├── licensing/                    # identidade/licenciamento
├── desenvolvimento/              # build, scanner, harness e testes
│   └── testes/
├── distribuicao/                 # instruções do pacote executável
├── docs/                         # documentação pública curada
└── assets/screenshots/           # capturas atuais da interface
```

O repositório público **não inclui** histórico de prompts, logs de validação, evidências intermediárias, ZIPs internos, patches ou bundles antigos da árvore mestre de desenvolvimento.

## Executar em modo fonte

### Requisitos

- Windows 10/11
- Python 3.12 recomendado
- PowerShell disponível no sistema

Crie um ambiente virtual e instale as dependências:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Para iniciar pela interface gráfica:

```powershell
python main_gui.py
```

ou use:

```text
INICIAR_CONFIGURADOR_TI.cmd
```

> Algumas funções dependem de Windows real e algumas ações administrativas solicitam elevação apenas quando necessário.

## Testes e QA

A candidata-base REBRAND GLOBAL R1 registrou:

- **34 suítes**
- **844 testes**
- **841 PASS**
- **3 SKIP**
- **0 FAIL**
- `compileall`: PASS
- scanner de branding: PASS
- harness portátil/Linux: `PASS_WITH_NATIVE_PENDING`

Para executar a suíte incluída no repositório:

```powershell
python -m unittest discover -s desenvolvimento/testes -p "test_*.py"
```

A suíte possui testes que dependem de PyQt6 e alguns gates condicionais a Windows. Consulte [`docs/TESTING.md`](docs/TESTING.md).

## Build

O pipeline oficial usa PyInstaller. Para instalar dependências de desenvolvimento:

```powershell
python -m pip install -r requirements-dev.txt
```

No Windows, o build portátil pode ser iniciado por:

```text
CRIAR_EXE_E_PENDRIVE_TI_v5_0.bat
```

O pipeline preserva saídas anteriores, gera manifesto/checksums e rejeita uma distribuição que viole os gates de higiene definidos pelo projeto.

## Segurança e limites

Este projeto **não é um RMM de produção** e a Central/Backend atuais são referências locais de QA. O desenho atual evita shell remoto livre, upload/execução arbitrária e remediação automática sem confirmação.

O repositório não contém chaves privadas, credenciais reais ou estado persistente de usuário. Consulte [`docs/SECURITY.md`](docs/SECURITY.md).

## Screenshots

As capturas antigas foram removidas durante o rebranding para evitar apresentar telas históricas como se fossem da versão atual. A pasta [`assets/screenshots/`](assets/screenshots/) está reservada para novas capturas da candidata rebatizada.

## Roadmap

Os próximos gates incluem:

- validação completa em Windows real;
- build e smoke de `ConfiguradorTI.exe` e `ConfiguradorTIAgent.exe`;
- validação de serviço Windows / LocalService / ACL / DPAPI;
- validação da Central em navegador real;
- captura de screenshots atuais;
- consolidação da documentação de release.

Veja [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Autor

**Juan Pablo Oliveira de Azevedo**

- LinkedIn: https://www.linkedin.com/in/juanpabloazevedo
- GitHub: https://github.com/juanpablooliveradeazevedo

---

Projeto pessoal em desenvolvimento. O conteúdo deste repositório representa uma versão de portfólio e QA, não uma declaração de prontidão para produção.
