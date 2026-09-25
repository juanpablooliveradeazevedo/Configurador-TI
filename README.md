# Configurador TI 🖥️

Projeto pessoal em desenvolvimento voltado para **diagnóstico, inventário, manutenção, monitoramento e apoio à administração de computadores Windows**.

> 🚧 Projeto em desenvolvimento ativo.
>
> Este repositório funciona atualmente como **portfólio e documentação pública do projeto**.

## 📌 Visão geral

O Configurador TI surgiu a partir da observação de rotinas recorrentes de suporte técnico e da ideia de reunir, em uma única interface, informações e ferramentas que normalmente ficam distribuídas entre diferentes utilitários, comandos e telas do Windows.

O projeto continua sendo desenvolvido de forma independente como iniciativa pessoal de estudo, automação e evolução prática em desenvolvimento de software.

Atualmente, a aplicação reúne recursos relacionados a:

- diagnóstico do computador;
- inventário de hardware e sistema;
- rede e DNS;
- armazenamento e SMART;
- processos e serviços;
- monitoramento;
- análise defensiva;
- relatórios e auditoria;
- automação de tarefas administrativas;
- componentes experimentais de gerenciamento de endpoints.

## 🎯 Objetivos

- Centralizar informações técnicas relevantes para suporte e administração de computadores Windows.
- Reduzir tarefas manuais de diagnóstico e coleta de informações.
- Criar uma interface mais organizada para rotinas técnicas.
- Utilizar o projeto como ambiente prático de aprendizado em desenvolvimento, automação, redes, Windows, segurança e qualidade de software.

## 🛠️ Tecnologias

- Python
- PyQt6
- PowerShell
- WMI / CIM
- SQLite
- PyInstaller
- Git
- Ferramentas e APIs nativas do Windows

## 📈 Status

🚧 **Em desenvolvimento ativo**

## ⚙️ Principais funcionalidades

O Configurador TI reúne diferentes recursos técnicos em uma única aplicação para Windows.

### 🖥️ Diagnóstico e inventário

- Coleta de informações do sistema operacional e hardware
- Informações de CPU, memória e armazenamento
- Organização de dados técnicos do computador
- Centralização de informações normalmente distribuídas em diferentes ferramentas do Windows

### 🌐 Rede e conectividade

- Informações de adaptadores de rede
- Consulta e diagnóstico de DNS
- Informações de IP e conectividade
- Recursos de análise de rede

### 💾 Armazenamento

- Informações sobre discos e unidades
- Consulta de dados S.M.A.R.T. quando suportados
- Apoio ao diagnóstico de armazenamento

### ⚙️ Processos e serviços

- Visualização de processos
- Consulta de serviços do Windows
- Informações de estado e funcionamento
- Recursos administrativos controlados

### 📊 Monitoramento

- Monitoramento de recursos do computador
- Coleta de informações operacionais
- Histórico e acompanhamento de estados
- Apoio à identificação de alterações no sistema

### 🛡️ Segurança e análise defensiva

- Consulta de informações relacionadas à segurança do endpoint
- Informações de BitLocker, TPM e Secure Boot quando disponíveis
- Informações de antivírus, Microsoft Defender e Firewall
- Recursos de baseline e comparação de estados
- Timeline para apoio à análise técnica

### 🖧 Gerenciamento de endpoints

O projeto também possui componentes em evolução para estudo e implementação de:

- Agent para Windows
- Serviço Windows
- Central Web
- Comunicação entre endpoints
- Gerenciamento de dispositivos
- Identidade e licenciamento

Esses componentes permanecem em desenvolvimento e são utilizados principalmente para estudo, testes e evolução da arquitetura.

## 🏗️ Arquitetura

O projeto evoluiu de uma aplicação desktop local para uma arquitetura mais modular.

```text
Configurador TI
│
├── Aplicação Desktop
│   ├── Interface gráfica
│   ├── Diagnóstico
│   ├── Inventário
│   ├── Rede
│   ├── Armazenamento
│   └── Ferramentas administrativas
│
├── Agent
│   ├── Coleta de informações
│   └── Comunicação com componentes de gerenciamento
│
├── Serviço Windows
│
├── Central Web
│
└── Control Plane / gerenciamento de endpoints
```

A arquitetura continua sendo revisada conforme novas funcionalidades são desenvolvidas e testadas.

## 🧪 Desenvolvimento e qualidade

O projeto é desenvolvido de forma incremental, com foco em:

- implementação por etapas;
- testes automatizados;
- testes funcionais;
- revisão de regressões;
- validação de interface;
- documentação técnica;
- controle de versões;
- análise de falhas;
- possibilidade de rollback entre versões.

A versão atual possui uma suíte automatizada com centenas de testes utilizados durante o processo de evolução do projeto.

Validações específicas que dependem diretamente do ambiente Windows também são realizadas separadamente dos testes automatizados.

## 🤖 Uso de IA no desenvolvimento

Ferramentas de IA generativa são utilizadas como apoio durante o desenvolvimento para atividades como:

- planejamento de implementações;
- prototipação;
- análise e revisão de código;
- depuração;
- geração e revisão de testes;
- documentação;
- análise de regressões.

A definição dos objetivos do projeto, requisitos, decisões funcionais, validação dos resultados e direcionamento da evolução são conduzidos por mim.

O uso de IA faz parte do processo de desenvolvimento e aprendizado do projeto, funcionando como ferramenta de apoio e não como substituição da validação técnica.

## 🗺️ Roadmap

Alguns dos próximos objetivos do projeto incluem:

- continuar aprimorando a interface e experiência de uso;
- aumentar a cobertura de diagnóstico;
- evoluir os componentes de gerenciamento de endpoints;
- ampliar testes em ambientes Windows reais;
- melhorar observabilidade e auditoria;
- aprimorar documentação;
- preparar uma distribuição independente mais simples;
- avaliar a publicação futura de partes adicionais do código-fonte.

## 📷 Screenshots

Capturas da aplicação serão adicionadas conforme a nova identidade visual independente do projeto for consolidada.

## 📦 Disponibilidade

🚧 **Projeto em desenvolvimento ativo**

Este repositório funciona atualmente como apresentação pública e documentação do projeto.

O conteúdo disponibilizado publicamente poderá ser ampliado conforme novas versões forem revisadas e preparadas para distribuição.

## 👨‍💻 Autor

**Juan Pablo Oliveira de Azevedo**

Estudante de Análise e Desenvolvimento de Sistemas.

[LinkedIn](https://www.linkedin.com/in/juan-pablo-0764ba247/) • [GitHub](https://github.com/juanpablooliveradeazevedo)

O projeto está sendo evoluído de forma incremental, com testes funcionais, revisões de interface, documentação e validação de diferentes módulos.
