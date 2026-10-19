# Przygotowanie Kali OSAI — metodologia Yhwach-driven (PL)

Kompletny przewodnik przygotowania świeżej maszyny **Kali Linux 2026** do pracy wg metodologii *Yhwach-driven*: silnik stanu + **Claude Code (Opus 4.8)** jako operator, HexStrike / BloodHound / filesystem jako MCP, lokalny Obsidian vault jako notatnik. Po lekturze powinieneś mieć zieloną pętlę `yhwach_next → reason → act → fold back` na własnym labie.

> **Target:** Kali Linux 2026 · Python ≥ 3.11 · autoryzowane środowiska laboratoryjne.

---

## Spis treści

1. [Filozofia](#1-filozofia-metodologii)
2. [Prerekwizyty](#2-prerekwizyty)
3. [Claude Code (Opus 4.8)](#3-claude-code-opus-48)
4. [Yhwach — silnik + UI](#4-yhwach--silnik--ui)
5. [HexStrike-AI](#5-hexstrike-ai)
6. [BloodHound-MCP](#6-bloodhound-mcp)
7. [Arsenał ofensywny](#7-arsena-ofensywny)
8. [Pre-staged tooling (dostarczane osobno)](#8-pre-staged-tooling-dostarczane-osobno)
9. [Drzewo `~/osai`](#9-drzewo-osai)
10. [Skrypt do screenshotów](#10-skrypt-do-screenshotów)
11. [Konfiguracja MCP](#11-konfiguracja-mcp)
12. [Obsidian vault (lokalny)](#12-obsidian-vault-lokalny)
13. [Weryfikacja setupu przez Claude](#13-weryfikacja-setupu-przez-claude)
14. [Nauka metodologii — laby + UI yhwach](#14-nauka-metodologii--laby--ui-yhwach)
15. [Dyscyplina](#15-dyscyplina)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. Filozofia metodologii

Metodologia stoi na **trzech filarach**:

1. **Yhwach** — silnik stanu + planer + handoff. Mała baza SQLite + CLI/MCP, która trzyma pełny obraz zaangażowania: hosty, serwisy, powierzchnie, findings, poświadczenia, taski, tunele, próby i pokrycie skanów. **Yhwach nie wywołuje modelu.**
2. **Claude Code (Opus 4.8)** — operator. Czyta handoff od Yhwach, rozumuje, wybiera komendę, odpala narzędzie, zwija wynik z powrotem do Yhwach. Pętla.
3. **Obsidian vault (lokalny)** — notatnik narracyjny. Yhwach trzyma *atomy* (hosts/creds/findings/proofs), vault trzyma *prozę* (attack chains, write-upy, screenshoty). Bez Obsidian MCP — pliki są pisane bezpośrednio.

Dookoła tego siedzi **stos MCP**: HexStrike (enum + web), BloodHound-MCP (AD reasoning), filesystem, Metasploit (session handler), hashcat, winremote. Wszystko loopback-only.

> **Zasada:** Yhwach to **jedyne źródło prawdy**. Jeśli coś nie jest w jego bazie, to się nie wydarzyło. Każda próba atakowa kończy się `yhwach_outcome`. Każdy flag kończy się `yhwach_proof` z screenshotem. Nieudokumentowany atak zostanie powtórzony po kompaktowaniu kontekstu.

### Punktacja egzaminu

- 100 pkt total, **75 do zdania**, 8 celów, 8 godzin.
- AI-vector ×~4 (15 pkt każdy) · standalone AI ×1 (15 pkt) · traditional ×~2 (10 pkt) · DC flag (5 pkt).
- **Same AI = 75 = pass bar.** AI pierwsze, zawsze. Standalone AI nie ma prereków — 15 pkt za darmo, rób na początku.

---

## 2. Prerekwizyty

- **Maszyna**: Kali Linux 2026, minimum 8 GB RAM, 60 GB wolnego, 4 rdzenie. VM w VMware/VirtualBox z `bridged` albo `NAT + Host-Only`.
- **Python 3.11+**, `git`, `pipx`, `jq`, `sqlite3`, `curl`.
- **Node.js 20+** i `npm` (dla MCP filesystem przez `npx`).
- **VPN do laba** — profil `.ovpn` dostarczony przez prowadzącego.
- **Konto Anthropic** z dostępem do Claude Code (API key albo Max plan).
- **Monitor 1920×1080+** — screenshoty flag muszą pokazywać whoami/hostname + `proof.txt` w jednej klatce.

Zainstaluj pakiety systemowe:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip pipx git jq sqlite3 \
                    curl wget nodejs npm build-essential xclip imagemagick \
                    openvpn resolvconf
pipx ensurepath
exec zsh
```

> **Uwaga:** metodologia zakłada pracę pod użytkownikiem `kali` z domowym katalogiem `~/osai`. Jeśli używasz innego usera — podmień ścieżki w konfiguracjach poniżej, ale zachowaj strukturę `~/osai/current/*`.

---

## 3. Claude Code (Opus 4.8)

Operator. Rozumuje i odpala narzędzia.

**Instalacja CLI:**

```bash
npm install -g @anthropic-ai/claude-code
```

**Pierwsze uruchomienie + autoryzacja:**

```bash
claude
# zaloguj przez Max/Pro albo wklej ANTHROPIC_API_KEY
```

**Ustaw default model na Opus 4.8** — reasoning jest wart tokenów. Edytuj `~/.claude/settings.json`:

```json
{
  "model": "claude-opus-4-8",
  "modelSettings": {
    "claude-opus-4-8": { "effortLevel": "xhigh" }
  },
  "skipDangerousModePermissionPrompt": true,
  "theme": "auto",
  "agentPushNotifEnabled": true
}
```

`skipDangerousModePermissionPrompt` wyłącza modalkę "czy wejść w yolo mode" za każdym razem. Odpalaj zawsze `claude --dangerously-skip-permissions` na egzaminie — Yhwach i tak loguje każdą próbę.

---

## 4. Yhwach — silnik + UI

Serce metodologii. Wszystko inne jest tylko konsumentem tego stanu.

**Klonuj i zainstaluj (z UI):**

```bash
git clone https://github.com/saymyname-sec/yhwach ~/yhwach
cd ~/yhwach
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mcp,ui]"     # UI extra wymagane dla `yhwach ui`
```

**Weryfikacja:**

```bash
yhwach --version        # 0.1.0 lub nowsze
yhwach persona | tail -1
yhwach doctor           # preflight checklist — exit 0 oznacza, że silnik działa
```

**PATH na stałe** — dodaj do `~/.zshrc`:

```bash
source ~/yhwach/.venv/bin/activate
export YHWACH_DB=~/osai/current/state/yhwach.db
```

### UI — podgląd świata w przeglądarce

Yhwach wystawia **live board** (world model + aktywność) jako lokalny serwer na `127.0.0.1:8799`. Czysto read-only, loopback-only.

```bash
yhwach ui --lab <nazwa-laba>            # port 8799 domyślnie
yhwach ui --lab <nazwa-laba> --redact   # maskuje sekrety w vault (demo mode)
```

**Trzymaj UI otwarte w drugim oknie przez cały engagement** — widzisz co Claude właśnie zrobił (hosty, credy, findingi, próby) bez pytania go o stan.

> `yhwach ui` z zasady odmawia binda na `0.0.0.0`/`::` — to jest celowe. Nie próbuj go wystawiać na sieć.

---

## 5. HexStrike-AI

151 narzędzi enum/web pod jednym MCP. Działa jako HTTP server na loopback.

```bash
git clone https://github.com/0x4m4/hexstrike-ai ~/osai/hexstrike-ai
cd ~/osai/hexstrike-ai
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate
pip install -r requirements.txt

# serwer
python3 hexstrike_server.py --port 8888 --host 127.0.0.1 &

# firewall — zablokuj publiczne interfejsy
sudo iptables -A INPUT -p tcp --dport 8888 ! -i lo -j DROP
```

> **OPSEC:** HexStrike wystawia 151 narzędzi bez autoryzacji. Jeśli zapomnisz firewalla, każdy w labie może Ci odpalić `metasploit_run` z Twojej maszyny. Po każdym tunelu Ligolo przeczytaj `iptables -L` ponownie — pivot może zmienić routing i odsłonić port.

Pamiętaj: do shellingu/payloadów **nie używaj** HexStrike'owego `metasploit_run` — to one-shot bez persistence. Session work idzie przez osobny Metasploit MCP.

---

## 6. BloodHound-MCP

Pyta BloodHounda po ludzku. "Pokaż najkrótszą ścieżkę do DA" zamiast ręcznych Cypher queries.

```bash
# BloodHound CE (collector + GUI przez docker)
pipx install bloodhound-ce
mkdir -p ~/bloodhound-ce && cd ~/bloodhound-ce
curl -L https://ghst.ly/getbhce -o docker-compose.yml
docker compose up -d

# MCP
git clone https://github.com/MorDavid/BloodHound-MCP-AI ~/repos/BloodHound-MCP-AI
cd ~/repos/BloodHound-MCP-AI
pip install -r requirements.txt --break-system-packages

# połączenie do Neo4j
export NEO4J_URL=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=<to co ustawiłeś w BHCE>
```

MCP odpala się jako stdio script bezpośrednio z `~/repos/BloodHound-MCP-AI/BloodHound-MCP.py` — konfiguracja w sekcji 11.

---

## 7. Arsenał ofensywny

Narzędzia, które Yhwach *renderuje i odpala*. Większość jest już w Kali 2026.

**Z repo Kali (apt):**

```bash
sudo apt install -y \
  nmap netexec smbmap enum4linux-ng ldap-utils \
  impacket-scripts evil-winrm nuclei ffuf sqlmap \
  freerdp2-x11 seclists gpp-decrypt responder \
  john hashcat hydra proxychains4 nikto whatweb \
  wfuzz feroxbuster gobuster dnsrecon dnsenum
```

**Przez pipx:**

```bash
pipx install certipy-ad          # ADCS
pipx install bloodyAD            # ACL abuse
pipx install coercer             # PetitPotam/PrintSpooler
pipx install impacket            # jeśli apt za stary
pipx install pypykatz
pipx install ldapdomaindump
```

**Binaria pobierane:**

```bash
# kerbrute
sudo curl -sL -o /usr/local/bin/kerbrute \
  https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
sudo chmod +x /usr/local/bin/kerbrute

# ligolo-ng — proxy (agent dostarczany osobno, zobacz sekcję 8)
mkdir -p ~/osai/tools/ligolo && cd ~/osai/tools/ligolo
curl -sL -o proxy.tgz https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_linux_amd64.tar.gz
tar xzf proxy.tgz

# chisel — fallback do ligolo
curl -sL https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz | gunzip > /usr/local/bin/chisel
sudo chmod +x /usr/local/bin/chisel
```

---

## 8. Pre-staged tooling (dostarczane osobno)

Niestandardowe artefakty, które otrzymasz **oddzielnie** przed egzaminem/engagementem — nie buduj ich sam, nie szukaj zamienników. Rozpakuj do `~/osai/arsenal/`:

| Plik | Rola |
| --- | --- |
| `CLAUDE.md` | Engagement brain / Yhwach-driven router. Trafia do `~/.claude/CLAUDE.md`. Ładuje się w każdym turnie. |
| `enum_playbook.md` | Referencyjna playbook enumeracji (ports, services, techniki per surface). |
| `svcmon.exe` | Obfuskowany agent Ligolo pod Windowsa (AV/EDR-evasive). Deployment renderuje `yhwach_pivot`. |
| **revshell generator** | Skrypt do generowania reverse shelli (Capstone / C# XOR). Instrukcja uruchomienia w zestawie. |

**Co robisz po otrzymaniu zestawu:**

```bash
mkdir -p ~/osai/arsenal
# rozpakuj zestaw do ~/osai/arsenal/

# CLAUDE.md -> ~/.claude/CLAUDE.md
cp ~/osai/arsenal/CLAUDE.md ~/.claude/CLAUDE.md

# enum_playbook.md -> ~/.claude/Enum_playbook.md (ładowany ad-hoc przez Claude)
cp ~/osai/arsenal/enum_playbook.md ~/.claude/Enum_playbook.md
```

Nie modyfikuj plików z zestawu. Jedna kopia na egzamin, kolejna do testów. Jeśli potrzebujesz nowego revshella mid-exam — używaj dostarczonego generatora, nigdy nie kompiluj na targecie.

---

## 9. Drzewo `~/osai`

Dyscyplina lokalizacji — każdy plik ma swoje miejsce. Nigdy `$HOME` ani `/tmp`.

```
~/osai/
├── bin/                      # pomocnicze skrypty operatora
├── arsenal/                  # pre-staged (CLAUDE.md, enum_playbook, svcmon, revshell gen)
├── hexstrike-ai/             # HexStrike server + MCP
├── tools/                    # ligolo, chisel, własne skrypty
│   └── claude/               # hashcat_mcp.py, adaptix_mcp.py, inne custom MCP
├── notes/                    # notatki do labów ukończonych
├── results/                  # eksporty raportów yhwach
├── labs/                     # jeden katalog per lab
│   └── <lab-name>/
│       ├── state/            # yhwach.db + logi + pidy
│       │   └── yhwach.db
│       ├── recon/            # skany: <host>-<tool>.txt
│       ├── loot/             # exfil, klucze, hashe
│       ├── screenshots/      # PROOFY — jedno zdjęcie = 10-15 pkt
│       ├── scripts/          # ad-hoc PoC skrypty
│       ├── chains/           # frozen attack chains (markdown)
│       └── tools/            # per-lab pre-staged (jeśli różne porty)
└── current -> labs/<active-lab>    # symlink do aktywnego laba

~/ObisidanOSAI/
└── <lab-name>/                 # proza — scaffoldowana przez notekit
    ├── _RESUME.md               # regenerowany co 10 min z yhwach.db
    ├── index.md
    ├── overview.md
    ├── attack-chain.md
    ├── credentials.md
    ├── network-map.md
    ├── next-steps.md
    ├── exhausted-approaches.md
    ├── hosts/
    ├── findings/
    ├── chains/
    └── checkpoints/
```

**Scaffolding:**

```bash
mkdir -p ~/osai/{bin,arsenal,tools/claude,notes,results,labs}
mkdir -p ~/ObisidanOSAI
```

---

## 10. Skrypt do screenshotów

Jedyny lokalny helper, którego potrzebujesz na egzaminie — reszta dyscypliny jest po stronie Yhwach + operatora, nie hooków Claude Code.

**`shot.sh`** (dostarczany razem z yhwach repo w `~/yhwach/notekit/shot.sh`) — robi screenshot aktywnego okna i wypala w rogu UTC + local timestamp. Używany przed każdym `yhwach_proof` oraz w milestone'ach (shell na nowym hoście, pierwszy DA, pierwszy pivot).

```bash
# jednorazowo
chmod +x ~/yhwach/notekit/shot.sh

# użycie
~/yhwach/notekit/shot.sh <nazwa>
# -> ~/osai/current/screenshots/<nazwa>-<utc-ts>.png
```

Potrzebne pakiety (jeśli brak):

```bash
sudo apt install -y imagemagick scrot
pip install Pillow --break-system-packages
```

Claude wywołuje `shot.sh` automatycznie w punktach wymaganych przez metodologię — nie klikaj screenshotów ręcznie.

---

## 11. Konfiguracja MCP

Pełny stos — każdy server stdio, wszystko loopback. Edytuj `~/.claude.json` → sekcja `mcpServers`:

```json
{
  "mcpServers": {
    "yhwach": {
      "type": "stdio",
      "command": "/home/kali/yhwach/.venv/bin/yhwach",
      "args": ["mcp"],
      "env": { "YHWACH_DB": "/home/kali/osai/current/state/yhwach.db" }
    },
    "hexstrike-ai": {
      "command": "python3",
      "args": ["/home/kali/osai/hexstrike-ai/hexstrike_mcp.py", "--server", "http://localhost:8888"],
      "timeout": 300
    },
    "bloodhound": {
      "type": "stdio",
      "command": "python3.13",
      "args": ["/home/kali/repos/BloodHound-MCP-AI/BloodHound-MCP.py"]
    },
    "metasploit": {
      "command": "bash",
      "args": ["-c", "cd /home/kali/osai/metasploit-framework && bundle exec ./msfmcpd --enable-dangerous-actions"]
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/kali/osai", "/tmp"]
    },
    "hashcat": {
      "type": "stdio",
      "command": "python3.13",
      "args": ["/home/kali/osai/tools/claude/hashcat_mcp.py"],
      "env": {
        "CRACK_WORKDIR": "/home/kali/osai/current/loot/cracking",
        "WORDLIST": "/usr/share/wordlists/rockyou.txt",
        "RULES_DIR": "/usr/share/hashcat/rules"
      }
    },
    "winremote": {
      "type": "stdio",
      "command": "/home/kali/.local/bin/winremote-mcp",
      "args": ["--transport", "stdio", "--enable-all"],
      "env": { "DISPLAY": ":77" }
    }
  }
}
```

### Co który MCP daje

| MCP | Primary role |
| --- | --- |
| `yhwach` | Stan + plan + handoff. **Pytaj go co turn.** |
| `hexstrike-ai` | Enum + web. Nmap/nuclei/ffuf/netexec/enum4linux-ng. |
| `bloodhound` | Natural-language queries do grafu AD. |
| `metasploit` | Session handler. **Jedyny** do sessions. Nigdy przez HexStrike. |
| `filesystem` | Czytanie/zapisywanie plików poza CWD operatora. |
| `hashcat` | Background cracking jobs — start/status/results. |
| `winremote` | GUI control na Kali (dla Windows RDP targets). |

> **OPSEC:** MCP serwery **same są powierzchnią ataku** (tool poisoning, CVE-2025-49596). Odpalaj tylko zweryfikowane. Każdy serwer ładuje swoje schematy w każdym turnie — trzymaj listę chudą.

---

## 12. Obsidian vault (lokalny)

Narracja. Prose, screenshoty, `_RESUME.md`. Bez MCP — pliki wprost.

```bash
sudo apt install -y flatpak
flatpak install -y flathub md.obsidian.Obsidian
# Obsidian -> "Open folder as vault" -> ~/ObisidanOSAI/
```

Skrypty notekit (scaffoldują strukturę per lab) są w `~/yhwach/notekit/`:

```bash
~/yhwach/notekit/scaffold_vault.sh <lab-name>   # scaffold hosts/, findings/, chains/, _RESUME.md...
~/yhwach/notekit/shot.sh <nazwa>                # screenshot z UTC+local timestamp wypalonym w rogu
```

> **Zasada:** Yhwach.db = **atomy** (host X stage foothold, cred X valid na Y). Obsidian = **proza** (dlaczego, jak, pełna komenda, output, screenshot). *Jedno bez drugiego nie wystarczy do raportu.*

---

## 13. Weryfikacja setupu przez Claude

**Nie weryfikuj setupu manualnie.** Po zainstalowaniu wszystkiego z sekcji 2–12 odpal Claude Code w `~/osai` i pozwól mu samemu sprawdzić stan maszyny. Operator robi to szybciej, dokładniej, i od razu widzi gdzie czegoś brakuje.

**Krok 1 — odpal Claude Code:**

```bash
cd ~/osai
claude --dangerously-skip-permissions
```

**Krok 2 — wklej jeden z poniższych promptów (wariant startowy):**

```
Jestem po świeżej instalacji wg docs/setup-pl.md z yhwach repo. Twoje zadanie:

1. Odpal `yhwach doctor` i zinterpretuj wynik.
2. Sprawdź że MCP: yhwach, hexstrike-ai, bloodhound, filesystem, metasploit, hashcat, winremote
   są widoczne i connected (`/mcp`).
3. Zweryfikuj że HexStrike żyje: `curl -s http://127.0.0.1:8888/health`.
4. Sprawdź że struktura ~/osai/ zgadza się z docs/setup-pl.md sekcja 9.
5. Sprawdź że ~/osai/arsenal/ zawiera: CLAUDE.md, enum_playbook.md, svcmon.exe,
   revshell generator (dostarczane osobno).
6. Zweryfikuj że `~/yhwach/notekit/shot.sh` istnieje i jest wykonywalny
   (`imagemagick`, `scrot`, `Pillow` zainstalowane).
7. Sprawdź ~/.claude/CLAUDE.md i ~/.claude/Enum_playbook.md.
8. Czego brakuje — stwórz. Co jest źle skonfigurowane — popraw.
9. Zrób screenshoty każdego kroku weryfikacji do ~/osai/results/setup-check/.
10. Napisz raport: co działa, co naprawiłeś, co wymaga interwencji ode mnie.
```

Claude Code **sam**:

- Uruchomi `yhwach doctor` i przeczyta checklistę.
- Zrobi `curl` na HexStrike health endpoint.
- Przeleci strukturę katalogów (`ls`, `test -d`, `test -x`).
- Sparsuje `~/.claude/settings.json` i `~/.claude.json`.
- Dla brakujących katalogów — `mkdir -p`.
- Dla błędnej konfiguracji MCP — poprawi `~/.claude.json`.
- Dla brakującego arsenału — **zgłosi do Ciebie** (nie dostarczy sam, bo CLAUDE.md/revshell/svcmon są dostarczane osobno).
- Wywoła `~/yhwach/notekit/shot.sh` do każdego checkpointa.
- Zwróci strukturalny raport.

**Krok 3 — zaakceptuj albo dopytaj.** Jeśli raport mówi "wszystko zielone poza arsenałem" — rozpakuj zestaw do `~/osai/arsenal/` i poproś Claude o re-weryfikację.

> Jeżeli `yhwach doctor` wychodzi non-zero — nie przechodź dalej. Claude pokaże, który hard requirement padł (writable DB dir, loadable catalog) i co trzeba zrobić.

---

## 14. Nauka metodologii — laby + UI yhwach

Metodologię ćwiczysz **nie przez czytanie dokumentacji**, tylko przez odpalenie Claude na realnym (albo syntetycznym) labie i obserwowanie, jak pracuje.

### 14.1 Synthetic engagement (offline, bez targetu)

Yhwach ma wbudowany tryb demo — seed syntetycznego świata, bez sieci, bez skanera:

```bash
yhwach demo --kind lab          # albo: internal | web | cloud | bounty
yhwach ui --lab demo-lab        # otwórz http://127.0.0.1:8799 w przeglądarce
```

W drugim oknie odpal Claude:

```bash
cd ~/osai
claude --dangerously-skip-permissions
```

I wklej:

```
Lab: demo-lab (synthetic). Odpal `yhwach_recall`, pokaż mi stan, wywołaj `yhwach_next`
i wyjaśnij co proponujesz oraz dlaczego. Nie wykonuj komend — chcę tylko zobaczyć,
jak pętla wygląda od strony operatora.
```

To daje Ci **pół godziny na obserwację** cyklu `recall → status → next → reasoning` bez zużywania czasu laboratoryjnego.

### 14.2 Challenge laby

Realny trening — po doctor i demo:

- **OffSec Learn Labs** (Shadow Supply, Nexus itp.) — scenariusze AI-vector + traditional, dokładnie te same mechaniki co egzamin.
- **HackTheBox Pro Labs** — AD + lateral + pivot, dobre do części "traditional" i DC flag.
- **VulnLab** — mniej AI, więcej AD, przydatne dla krokowej praktyki BloodHounda i relayów.
- **Własny lab** — kontener z Vicuna/Llama + prosty RAG agent + mała domena Windows: pokrywa LLM01/02/06/07 z OWASP.

### 14.3 Prompty startowe

Yhwach repo trzyma referencyjne prompty do rozruchu engagementu w `~/yhwach/docs/prompts/`. Główny z nich (`yhwach-dev-master-prompt.md`) jest dev-focused, ale pokazuje format i intencję. **Dla operatora:** użyj poniższego prompta zaraz po stworzeniu laba:

```
Zaczynamy lab <nazwa>. VPN jest podniesiony. Scope: <CIDR1>, <CIDR2>, <CIDR3>.
Domena: <nazwa>, DC pod <ip>.

1. `yhwach_engage` z tymi parametrami.
2. Scaffold vault: `~/yhwach/notekit/scaffold_vault.sh <nazwa>`.
3. Odpal `yhwach ui --lab <nazwa>` w tle — chcę mieć podgląd.
4. `yhwach_enum` na całym scope (parallel po subnecie), potem `yhwach_gaps`,
   potem `yhwach_probe`.
5. Pokaż mi `yhwach_next` i uzasadnij top 3 kandydatów.
6. Nie wykonuj ataków bez mojej zgody; propozycje do akceptacji.
```

Od tego momentu pętla toczy się sama — Twoja rola to **akceptacja ruchów, screenshoty flag, i okazjonalne "stop, zmień kierunek"**.

### 14.4 UI yhwach jako kontrola jakości

Trzymaj `http://127.0.0.1:8799` otwarte przez cały engagement. Co widzisz:

- **Hosts board** — kto na jakim stage (`scanned → foothold → looted → pivoted`).
- **Credentials vault** — każdy nowy cred ląduje tutaj natychmiast (z `--redact` dla screenshotów).
- **Findings** — most-severe-first, oznaczone kategorią (LLM01/LLM02/.../INFO).
- **Attempts** — co Claude już próbował i czy się udało. **To jest Twoja detekcja "czy fold-back działa"**: jeśli widzisz, że Claude odpalił atak, a attempts się nie zmienił w ciągu 2 minut — to signal, że zapomniał o `yhwach_outcome`. Przerwij i przypomnij.
- **Objectives / scoreboard** — ile punktów już masz zbite, ile zostało do pass bar.
- **Tunnels** — jakie pivoty żyją.

### 14.5 Testowanie i screenshoty — Claude robi to sam

**Nie klikaj screenshotów ręcznie.** Claude ma dostęp do `~/yhwach/notekit/shot.sh` i wywołuje go w tych punktach, w których musi:

- Przed każdym `yhwach_proof` (bez screenshota operator odmówi gate'owania foothold→looted).
- Po każdym *(Pwn3d!)* / secretsdump sukcesie.
- W checkpointach milestone'ów (shell na nowym hoście, pierwszy DA, pierwszy pivot).

Zadaniem operatora w sekcji **14** jest obserwacja — czy pętla się toczy, czy fold-back się dzieje, czy UI pokazuje nowe atomy. Jeśli coś nie wygląda — przerywasz i promptujesz "zrób `yhwach_recall` i powiedz mi, co jest w attempts".

---

## 15. Dyscyplina

Co jest nieoptjonalne. Wyryj w pamięć.

1. **Każdy credential → `yhwach_cred`** w ciągu minuty od odkrycia. Z `--source` i `--host`.
2. **Każdy flag → screenshot FIRST, potem `yhwach_proof --host X --screenshot path`**. Bez screenshota = 0 pkt.
3. **Każda próba → `yhwach_outcome`**. Success konsumuje technikę, fail/blocked ją retire'uje i wrzuca do DEAD ENDS każdego kolejnego handoffa.
4. **Każdy pivot → `yhwach_pivot` + `yhwach_enum`** nowej podsieci natychmiast.
5. **Zero raw output do chatu.** Zawsze przez plik → grep → activate. `grep -c` pierwsze, nigdy nie czytaj >200-line file w całości.
6. **Kontekst jest jednorazowy.** Yhwach.db + vault to pamięć. Gdy kontekst robi się ciężki → `/clear` → `yhwach_recall` rehydruje w kilkuset tokenach.
7. **HexStrike loopback.** `iptables -L` po każdym tunelu Ligolo.
8. **Metasploit MCP do sesji, nie HexStrike.** HexStrike'owy `metasploit_run` jest one-shot bez persistence.
9. **Nigdy nie zgaduj komendy.** `subagent_type=Explore` na `~/repos/hacktricks` / `PayloadsAllTheThings` / `InternalAllTheThings` / `OSAI`. 20 sekund grepa < wyjście w kosmos.
10. **Scope.** Nic poza `scope.txt`. Nawet pingiem.

> **Red flag:** Jeśli przez >20 min nie wołałeś `yhwach_outcome`, to prawdopodobnie zapomniałeś. Zatrzymaj się i rozlicz się ze stanem przed następnym atakiem. Momentum ataku jest największym wrogiem fold-backa. **Patrz na UI yhwach — kolumna Attempts rośnie czy stoi?**

---

## 16. Troubleshooting

### MCP server shows "CONNECTION_CLOSED"

Zwykle: command w konfiguracji nie istnieje albo pythonowe env popsute. Weryfikuj ręcznie:

```bash
bash -c "cd /home/kali/osai/metasploit-framework && bundle exec ./msfmcpd --help"
```

Jak komenda nie startuje w shellu — nie wystartuje też jako MCP.

### `yhwach doctor` wychodzi non-zero

Przeczytaj checklistę — każdy fail jest jedno-liniowy. Najczęściej:

- `DB dir not writable` — `chmod +w ~/osai/current/state`
- `HexStrike unreachable` — serwer nie żyje albo port zablokowany (`curl 127.0.0.1:8888/health`)
- `UI extra not installed` — `pip install 'yhwach[ui]'`

### HexStrike zwraca 500 na scope-respecting narzędzia

Sprawdź że `~/osai/current/state/scope.txt` istnieje i że symlink `current` nie dangluje:

```bash
readlink -f ~/osai/current && cat ~/osai/current/state/scope.txt
```

### Yhwach "no engagement"

Nie wywołałeś `yhwach_engage`. Czasem po `/clear` Claude zapomina — poproś "zrób `yhwach_recall`".

### UI pokazuje "stan sprzed godziny"

Browser cache albo UI serwer padł. `curl 127.0.0.1:8799/_health` → jeśli 200, hard-reload w przeglądarce. Jeśli brak odpowiedzi, re-launch `yhwach ui --lab <lab>`.

### Screenshoty nie mają timestamp

`stamp-timestamp.py` nie działa — zazwyczaj brak PIL. `pip install Pillow --break-system-packages`.

### Chisel/Ligolo wysypuje się na "no sudo"

Ligolo-proxy potrzebuje `sudo` do stworzenia `tun0`. Jeśli nie masz passwordless sudo — przełącz się na `chisel`:

```bash
chisel server --port 11601 --reverse &
# na targecie:
chisel.exe client <KALI_IP>:11601 R:1080:socks
```

Daje SOCKS5 na `127.0.0.1:1080` → `proxychains4` i w drogę.

### Context compaction zjadł Twój fail-log

Właśnie dlatego `yhwach_outcome` jest obowiązkowe. Jeżeli zapomniałeś — zrób `yhwach_recall`, zobacz co jest w attempts, i dopisz brakujące outcomes ręcznie na podstawie `attack-chain.md` z vault.

---

**Następny krok:** rozpakuj zestaw z sekcji 8 do `~/osai/arsenal/`, odpal Claude w `~/osai`, wklej prompt z sekcji 13. Jeśli raport jest zielony — przejdź do sekcji 14 i puść `yhwach demo --kind lab` jako trening. Jeśli nie — Claude Ci powie, czego brakuje.

Powodzenia. **AI first. 75 to pass. Screenshot every flag.**
