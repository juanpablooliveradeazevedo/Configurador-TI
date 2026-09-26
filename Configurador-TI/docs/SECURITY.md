# Segurança e limites

## Escopo

O repositório público representa uma candidata de QA e portfólio. Ele não deve ser
interpretado como uma plataforma RMM ou serviço cloud pronto para produção.

## Princípios usados no projeto

- **Fail closed:** estados de autorização ou validação incertos não concedem permissão.
- **Privilégio sob demanda:** a interface não exige administração na abertura; ações específicas podem pedir elevação quando necessário.
- **Catálogo fechado:** o fluxo Fleet usa ações previamente definidas.
- **Sem shell remoto livre:** não existe endpoint genérico para executar PowerShell/comandos arbitrários.
- **Sem upload/execute remoto genérico.**
- **Mudança controlada:** ações transacionais usam preparação, confirmação, validação e rollback quando suportado.
- **Persistência de evidência:** revogação ou falhas não devem apagar silenciosamente provas técnicas.
- **Coleta mínima:** o sync Fleet evita dados brutos que não sejam necessários ao contrato atual.

## Segredos e estado local

Não versione:

- senhas;
- códigos de enrollment;
- tokens de sessão;
- identidades `.bin`;
- chaves privadas;
- bancos de estado;
- logs reais;
- relatórios com dados do equipamento;
- `agent-public.json` de um ambiente real.

O `.gitignore` contém regras para esses artefatos.

## Backend e Central

A referência atual é de QA local. Bind local, TLS de produção, observabilidade de
serviço, rotação de chaves, deploy, backup e hardening de infraestrutura exigem
trabalho adicional antes de qualquer exposição em rede.

## Windows

A implementação possui contratos para LocalService, ACL e DPAPI, mas a candidata
ainda possui gates nativos pendentes. Consulte [`WINDOWS_VALIDATION.md`](WINDOWS_VALIDATION.md).

## Divulgação de vulnerabilidades

Evite publicar credenciais, dumps, chaves ou dados sensíveis em Issues. Ao documentar
um problema de segurança, use dados sintéticos e descreva apenas o necessário para
reprodução.
