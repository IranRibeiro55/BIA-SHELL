# BIA Shell

**BIA Shell** é um assistente em PowerShell para equipes de TI e Suporte, com interface em modo texto, animações, resumo da máquina (usuário, AD, RAM, disco, IP) e dezenas de funções prontas para atendimento e diagnóstico.

Desenvolvido por **Iran Ribeiro** · [GitHub](https://github.com/IranRibeiro55)

---

## Índice

- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Como executar](#como-executar)
- [O que o BIA faz](#o-que-o-bia-faz)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Documentação dos menus](#documentação-dos-menus)
- [Configuração e personalização](#configuração-e-personalização)
- [Log e arquivos gerados](#log-e-arquivos-gerados)
- [Solução de problemas](#solução-de-problemas)
- [Licença](#licença)

---

## Requisitos

- **Windows** (testado em Windows 10/11 e Server)
- **PowerShell 5.1** ou superior (já incluso no Windows)
- Algumas opções exigem **elevação de administrador** (SFC, ponto de restauração, serviços, etc.)

---

## Instalação

1. Clone o repositório ou baixe os arquivos em uma pasta, por exemplo:
   ```
   C:\Ferramentas\BIA-Shell\
   ```

2. Mantenha na mesma pasta os três arquivos principais:
   - `BIA-Shell.ps1`
   - `BIA-UI.ps1`
   - `BIA-Launcher.bat`

3. (Opcional) Se o PowerShell bloquear a execução de scripts, abra o PowerShell **como Administrador** e execute:
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```

---

## Como executar

- **Recomendado:** dê duplo clique em **`BIA-Launcher.bat`**.  
  Ele abre o PowerShell e executa o BIA com a política de execução adequada.

- **Pelo PowerShell:**
  ```powershell
  cd C:\caminho\para\BIA-Shell
  powershell -ExecutionPolicy Bypass -File .\BIA-Shell.ps1
  ```

- **Pelo Explorador de Arquivos:** clique com o botão direito em `BIA-Shell.ps1` → **Executar com PowerShell** (se a política permitir).

---

## O que o BIA faz

- **Tela inicial:** resumo da máquina (usuário, computador, domínio AD, SO, uptime, fabricante, modelo, RAM, disco, IP) e saudação (Bom dia / Boa tarde / Boa noite).
- **Cabeçalho em todas as telas:** usuário, computador e **IP** sempre visíveis.
- **Opção “Voltar ao início” (R):** volta ao resumo e à pergunta “Como posso ajudar?”.
- **Animações:** splash de carregamento, barras de progresso, spinner em operações longas, transições entre menus.
- **Menus:** Usuário, TI, Rede, AD, Utilitários, Playbooks, Informações do sistema, Diagnóstico rápido, **Impressoras**, **Azure (Connect/CLI)**, **Instalar aplicativos (winget)** e **Sobre** (créditos e link do GitHub).
- **Impressoras:** listar, definir padrão, adicionar/remover, página de teste, reiniciar spooler, limpar fila, ver trabalhos na fila.
- **Azure:** Connect-AzAccount, Get-AzContext, az login, az account show, instalar módulo Az ou Azure CLI.
- **Instalar aplicativos:** lista de apps via winget (7-Zip, Chrome, Firefox, Notepad++, VLC, Git, VS Code, PowerShell 7, Azure CLI, etc.).
- **Log:** ações registradas em `%TEMP%\BIA\BIA_Acoes.log`.
- **Export:** informações completas do sistema em TXT em `%TEMP%\BIA\`.

---

## Estrutura do projeto

| Arquivo            | Função |
|--------------------|--------|
| **BIA-Launcher.bat** | Atalho que inicia o PowerShell e executa o script. Use este para abrir o BIA. |
| **BIA-Shell.ps1**    | Script principal: fluxo, menus, funções (limpeza, rede, TI, AD, playbooks, diagnóstico, etc.). |
| **BIA-UI.ps1**       | Módulo de interface: cores, caixas, splash, barras de progresso, spinner, painel de informações. |
| **README.md**        | Esta documentação. |

O `BIA-Shell.ps1` carrega o `BIA-UI.ps1` no início (dot-source). Não renomeie nem separe os arquivos se quiser que tudo funcione como está.

---

## Documentação dos menus

### Menu principal

- **1 – Usuário** – Atendimento rápido ao usuário final.
- **2 – TI** – Ferramentas para administradores.
- **3 – Servidor / Active Directory** – AD, GPO, DNS, DHCP, repadmin, dcdiag, etc.
- **4 – Rede e Segurança** – Ping, tracert, netstat, firewall, winsock, mapear unidade, abrir \\computador.
- **5 – Utilitários** – Regedit, desligamento agendado, limpeza de disco, otimizar volumes, backup do registro, TeamViewer/AnyDesk, atalhos (Notepad, Calc, CMD, PowerShell), esvaziar Lixeira, variáveis de ambiente, clipboard, hash de arquivo, relatório de bateria, ativação do Windows, painéis (Programas, Rede, Energia, Som, Data/hora, Credenciais).
- **6 – Playbooks automáticos** – PC lento, sem internet, impressora travada (ações em sequência).
- **7 – Informações do sistema** – Resumo detalhado, export para TXT, uptime, **dashboard** (mesmo resumo da tela inicial).
- **8 – Diagnóstico rápido** – Health check (disco, RAM, rede, serviços), eventos de erro 24h, teste de conectividade, espaço em disco/RAM.
- **9 – Impressoras** – Listar, definir padrão, adicionar/remover, página de teste, reiniciar spooler, limpar fila, ver trabalhos.
- **10 – Azure** – Connect-AzAccount, Get-AzContext, az login, az account show, instalar módulo Az ou Azure CLI.
- **11 – Instalar aplicativos** – Instalação via winget (7-Zip, Chrome, Firefox, Notepad++, VLC, Git, VS Code, PowerShell 7, Azure CLI, Teams, Slack, etc.).
- **12 – Comandos e ferramentas (CMD / PowerShell)** – nslookup, Test-NetConnection, route, arp, whoami, variáveis de ambiente, tarefas agendadas, programas de inicialização, pendência de reinício, Windows Defender, DISM, relatório de bateria, ativação do Windows, Relatório de Confiabilidade, clipboard, hash de arquivo, esvaziar Lixeira, atalhos para painéis (Programas, Rede, Energia, Som, Data/hora, Credenciais), net share, net user, bloquear estação, processo por porta, WSL.
- **R – Ver resumo da máquina** – Volta à tela inicial (resumo + saudação).
- **S – Sobre** – Créditos e link do repositório (Iran Ribeiro / GitHub).
- **0 – Sair** – Encerra o BIA (exibe créditos ao sair).

---

### 1) Usuário – Atendimento rápido

| Opção | Descrição |
|-------|-----------|
| 1 | Limpeza básica: `%TEMP%` e `C:\Windows\Temp`. |
| 2 | Diagnóstico de internet: ping 8.8.8.8 e Google, flush DNS, release/renew IP. |
| 3 | `ipconfig /all` (com paginação). |
| 4 | Flush DNS. |
| 5 | Abre o painel do Windows Update. |
| 6 | Agenda CHKDSK C: /F /R (recomenda reinício). |
| 7 | Abre a pasta do usuário (`%USERPROFILE%`). |
| 8 | Abre “Este Computador”. |
| 9 | Reset de caches: Teams, Office, Edge, Chrome. |
| a | Abre Documentos, Desktop ou Downloads (submenu 1/2/3). |
| 0 | Voltar ao menu principal. |

---

### 2) TI – Ferramentas administrativas

| Opção | Descrição |
|-------|-----------|
| 1 | `gpupdate /force` (com spinner). |
| 2 | Abre o Visualizador de Eventos. |
| 3 | Abre Services (services.msc). |
| 4 | Abre o Monitor de Desempenho (perfmon). |
| 5 | Abre o Gerenciador de Tarefas. |
| 6 | Lista processos (tasklist). |
| 7 | Encerra processo por nome (taskkill). |
| 8 | Lista softwares instalados (WMIC – pode demorar). |
| 9 | Top 10 processos por CPU/RAM. |
| a | Abre Conexão Remota (mstsc). |
| b | Abre Gerenciamento do computador (compmgmt.msc) local. |
| c | Gerenciamento do computador **remoto** (pede nome do PC). |
| d | Abre Usuários e grupos locais (lusrmgr.msc). |
| e | Lista atualizações instaladas (hotfix). |
| f | Verificação SFC (arquivos de sistema) – pede confirmação. |
| g | Cria ponto de restauração. |
| h | Status do BitLocker. |
| i | Submenu: Assistência Remota (msra) ou Painel de Impressoras. |
| j | Sessões RDP ativas (`query session`). |
| k | `whoami /all`. |
| l | Tarefas agendadas (listar). |
| m | Programas de inicialização (Win32_StartupCommand). |
| n | Windows Defender: status e scan rápido. |
| o | `net share` (compartilhamentos). |
| p | Verificar pendência de reinício. |
| q | `net user` (usuários locais). |
| r | Bloquear estação (LockWorkStation). |
| s | Processo por porta (qual processo usa a porta X). |
| t | Relatório de Confiabilidade (perfmon /rel). |
| 0 | Voltar. |

---

### 3) Servidor – Active Directory

| Opção | Descrição |
|-------|-----------|
| 1–4 | Abre dsa.msc, gpmc.msc, dnsmgmt.msc, dhcpmgmt.msc. |
| 5 | `repadmin /replsummary`. |
| 6 | `repadmin /syncall /AdeP`. |
| 7 | `dcdiag`. |
| 8 | Diagnóstico AD rápido: nltest, klist, gpresult. |
| 0 | Voltar. |

---

### 4) Rede e Segurança

| Opção | Descrição |
|-------|-----------|
| 1–3 | Ping 8.8.8.8, tracert google.com, netstat -ano. |
| 4 | Reset Winsock e IP (recomenda reinício). |
| 5–6 | Desliga ou liga o Firewall do Windows. |
| 7 | Limpa ARP e faz release/renew DHCP. |
| 8 | Portas em uso (LISTEN/ESTABLISHED). |
| 9 | Mapear unidade de rede (pede letra e caminho UNC). |
| a | Abre pasta de rede (pede \\computador). |
| b | nslookup (consultar DNS). |
| c | Test-NetConnection (host e opcionalmente porta). |
| d | route print. |
| e | arp -a (tabela ARP). |
| f | ipconfig /displaydns (cache DNS). |
| 0 | Voltar. |

---

### 5) Utilitários

| Opção | Descrição |
|-------|-----------|
| 1 | Abre o Editor do Registro. |
| 2–3 | Agenda desligamento em 1h ou 2h. |
| 4 | Cancela desligamento agendado. |
| 5 | Limpeza de disco (Prefetch, cache de fontes). |
| 6 | Otimiza volumes (ReTrim, útil para SSD). |
| 7 | Backup do registro (exporta HKCU para `%TEMP%\BIA\`). |
| 8 | Abre TeamViewer ou AnyDesk, se instalados. |
| 9 | Atalhos: Bloco de notas, Calculadora, CMD, PowerShell. |
| a | Esvaziar Lixeira. |
| b | Variáveis de ambiente (listar). |
| c | Ver conteúdo do clipboard. |
| d | Hash de arquivo (SHA256). |
| e | Relatório de bateria (powercfg; abre HTML na Área de Trabalho). |
| f | Ativação do Windows (status). |
| g | Painéis: Programas (appwiz), Rede (ncpa), Energia, Som, Data/hora, Credenciais. |
| 0 | Voltar. |

---

### 6) Playbooks automáticos

Executam sequências prontas:

- **1 – PC lento:** limpa TEMP, Windows\Temp, flush DNS, release/renew IP.
- **2 – Sem internet:** reset Winsock e IP, flush DNS, release/renew IP.
- **3 – Impressora travada:** para o spooler, limpa a fila, reinicia o spooler.

---

### 7) Informações do sistema

- **1 – Resumo na tela** – SO, hardware, CPU, RAM, discos, rede, BIOS.
- **2 – Exportar pacote completo** – Gera TXT em `%TEMP%\BIA\` com systeminfo, WMI (OS, disk, rede, BIOS, etc.).
- **3 – Uptime** – Tempo ligado desde o último boot.
- **4 – Ver dashboard** – Mesmo resumo da tela inicial (usuário, máquina, AD, RAM, disco, IP).

---

### 8) Diagnóstico rápido (health check)

- **1 – Diagnóstico completo** – Disco (%), RAM (livre/uso), ping 8.8.8.8, serviços (Spooler, Dhcp, Dnscache, Winmgmt).
- **2 – Eventos de erro** – Últimos erros do System nas últimas 24h.
- **3 – Teste de conectividade** – Ping em 8.8.8.8, 1.1.1.1, www.google.com.
- **4 – Espaço em disco e memória** – Resumo rápido.

---

### 9) Impressoras

- **1 – Listar impressoras** – Nome, driver e porta.
- **2 – Definir impressora padrão** – Pede o nome da impressora.
- **3 – Abrir Painel de Impressoras** – `control printers`.
- **4 – Adicionar impressora** – Assistente do Windows (rundll32).
- **5 – Remover impressora** – Pede o nome.
- **6 – Imprimir página de teste** – Pede o nome (usa PrintManagement).
- **7 – Reiniciar serviço Spooler**.
- **8 – Limpar fila de impressão** – Mesmo playbook “Impressora travada”.
- **9 – Listar trabalhos na fila** – Por impressora.

---

### 10) Azure (Connect / CLI)

- **1 – Connect-AzAccount** – Login no Azure via PowerShell (módulo Az).
- **2 – Get-AzContext** – Ver contexto/assinatura atual.
- **3 – az login** – Login via Azure CLI.
- **4 – az account show** – Ver conta/assinatura da CLI.
- **5 – Instalar módulo Az** – `Install-Module Az -Scope CurrentUser`.
- **6 – Instalar Azure CLI** – Via winget (Microsoft.AzureCLI).

---

### 11) Instalar aplicativos (winget)

Menu com lista de aplicativos instaláveis via **winget** (Windows Package Manager). Basta escolher o número; o BIA executa `winget install <id>` com aceite de termos.

**Apps disponíveis (entre outros):** 7-Zip, Google Chrome, Firefox, Notepad++, VLC, Git, VS Code, PowerShell 7, Azure CLI, Windows Terminal, PuTTY, WinSCP, Java JRE, Python 3.12, Microsoft Teams, Zoom, Adobe Acrobat Reader, Microsoft Edge.

Requer **winget** instalado (incluído no Windows 10/11 atualizado).

---

### 12) Comandos e ferramentas (CMD / PowerShell)

Reúne comandos e ferramentas comuns de CMD e PowerShell em um único menu:

| Área | Opção | Descrição |
|------|-------|-----------|
| Rede | 1–5 | nslookup, Test-NetConnection (host+porta), route print, arp -a, ipconfig /displaydns. |
| Sistema | 6–a | whoami /all, variáveis de ambiente, tarefas agendadas, programas de inicialização, pendência de reinício. |
| Segurança / Manutenção | b–f | Windows Defender (status + scan), DISM RestoreHealth, relatório de bateria, ativação do Windows, Relatório de Confiabilidade. |
| Arquivos | g–i | Ver clipboard, hash de arquivo (SHA256), esvaziar Lixeira. |
| Atalhos | j | Programas, Rede, Energia, Som, Data/hora, Credenciais (Credential Manager). |
| Outros | k–o | net share, net user, bloquear estação, processo por porta, WSL --list. |

---

## Configuração e personalização

- **Cores e tema:** em `BIA-UI.ps1`, edite o hashtable `$script:BIA_Theme` (Title, Header, Menu, Success, Warning, Error, Accent, Muted).
- **Splash e loading:** em `BIA-UI.ps1`, funções `Show-BIASplash` e `Show-BIALoading` (mensagem, tempo, caracteres).
- **Novas opções no menu:** em `BIA-Shell.ps1`, no menu desejado:
  - Adicione uma linha em `Write-BIABox -Lines @(...)`.
  - No `switch ($op)` adicione um novo caso (ex.: `'X' { ... }`).

---

## Log e arquivos gerados

- **Log de ações:** `%TEMP%\BIA\BIA_Acoes.log` (registro de algumas ações escolhidas no menu).
- **Export de sistema:** `%TEMP%\BIA\SysInfo_<COMPUTERNAME>_<data-hora>.txt`.
- **Backup do registro:** `%TEMP%\BIA\RegBackup_<data-hora>.reg` (apenas HKCU, opção Utilitários > 7).

A pasta `%TEMP%\BIA` é criada automaticamente na primeira execução.

---

## Solução de problemas

- **“Script desabilitado” / política de execução:**  
  Em PowerShell **como Administrador**:  
  `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

- **Janela fecha rápido e não vejo erro:**  
  Defina `BIA_DEBUG=1` antes de executar (no prompt de comando ou no próprio launcher) e execute de novo. Ao sair, o BIA pede ENTER para fechar.

- **Algumas opções não funcionam:**  
  Várias funções (SFC, ponto de restauração, serviços, GPO, etc.) exigem **execução como Administrador**. Execute o `BIA-Launcher.bat` ou o PowerShell “Como administrador”.

- **IP não aparece no cabeçalho:**  
  O BIA usa o primeiro IPv4 não loopback. Se houver apenas interfaces virtuais ou VPN, o IP exibido pode ser de uma delas.

---

## Licença

Projeto de uso livre. Consulte o repositório para mais detalhes.

---

**Desenvolvido por Iran Ribeiro**  
**GitHub:** [https://github.com/IranRibeiro55](https://github.com/IranRibeiro55)
