# Notas da versão pública

Esta árvore foi preparada para portfólio a partir do ZIP:

`Configurador_TI_v5_0_REBRAND_GLOBAL_R1_2026-09-25`

SHA-256 da base recebida:

`3ff57f1a3ef404f35dd04b78d7cbc476137a36128fbe70a42a560024f9a0de9e`

## Mantido

- código-fonte da aplicação;
- Agent;
- Central Web;
- Control Plane;
- Fleet Protocol;
- Licensing;
- build e QA essenciais;
- suíte de testes;
- launcher e QSS;
- documentação pública curada.

## Não copiado para o repositório público

- evidências intermediárias;
- logs históricos;
- validações antigas;
- prompts de Work/IA;
- histórico de fases;
- patches;
- ZIPs internos de deployment;
- relatórios `RESULTADO_WORK_*`;
- bundles antigos;
- screenshots históricos;
- artefatos gerados.

## Duplicação removida

O arquivo `Configurador_TI_v5_0_FINAL.py` não foi copiado para esta árvore pública porque,
na base recebida, era **idêntico byte a byte** a `core_logic.py`:

`869492f25904a772a050ece8ce8bde315c34ea0eaceea20b2d3b2d43cbba7b56`

O teste estrutural público foi ajustado para não exigir a importação desse espelho.
A interface gráfica e o build oficial usam `core_logic.py`/`main_gui.pyw`.
