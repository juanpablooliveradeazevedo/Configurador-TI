# Testes e QA

## Evidência da candidata-base

A candidata mestre **REBRAND GLOBAL R1 (2026-09-25)** registrou:

| Métrica | Resultado |
|---|---:|
| Suítes | 34 |
| Testes | 844 |
| PASS | 841 |
| SKIP | 3 |
| Falhas de suíte | 0 |
| `compileall` | PASS |
| Scanner de branding | PASS |

Ambiente da regressão registrada:

- Linux
- Python 3.12
- Qt em modo offscreen

O harness da fase 2B terminou como `PASS_WITH_NATIVE_PENDING`.

## Executar os testes do repositório

```powershell
python -m unittest discover -s desenvolvimento/testes -p "test_*.py"
```

Para a suíte de interface:

```powershell
$env:QT_QPA_PLATFORM="offscreen"
python -m unittest discover -s desenvolvimento/testes -p "test_*.py"
```

## O que os testes cobrem

A suíte inclui regressões para:

- UX e responsividade;
- rede e DNS;
- baseline/análise defensiva;
- Timeline e auditoria;
- investigação/replay;
- monitoramento;
- postura do endpoint;
- Assistente Técnico;
- motor transacional;
- catálogo seguro;
- licenciamento;
- Fleet/Agent/Central;
- build/distribuição;
- hardening;
- rebranding.

## Gates que não são substituídos pelos testes portáveis

Os resultados portáveis **não equivalem** a validação nativa completa.

Ainda devem ser validados em Windows real:

- build do Technician;
- build do Agent;
- execução dos EXEs;
- `onefile` / `noconsole`;
- serviço Windows;
- LocalService;
- ACL;
- DPAPI;
- enrollment e persistência de identidade;
- restart do Agent;
- Central em navegador real;
- GUI do Technician;
- distribuição portátil.

Veja [`WINDOWS_VALIDATION.md`](WINDOWS_VALIDATION.md).
