# cvescout

[English](README.md) | **Polski**

[![tests](https://github.com/zember/cvescout/actions/workflows/tests.yml/badge.svg)](https://github.com/zember/cvescout/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Wyszukiwanie **najnowszych** CVE z żywych źródeł + agent Claude, który nie może odpowiadać z pamięci.

Dlaczego: model językowy zna tylko CVE sprzed swojej daty odcięcia wiedzy, więc pytany o „najnowsze” podaje stare.
`cvescout` pobiera dane w momencie zapytania, w oknie czasowym liczonym od dzisiejszej daty:

| Źródło | Co daje |
|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVE z ostatnich N dni lub od daty, CVSS, CWE, linki do exploitów |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | oficjalna lista CVE: ostatnie 30 dni bez limitów zapytań, ok. godzinę przed NVD, wersje podatne od producenta |
| [GitHub Advisory Database](https://github.com/advisories) | porady dla bibliotek open source: pakiet, podatne wersje, wersja z poprawką |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | podatności aktywnie wykorzystywane (filtr po `dateAdded`) |
| [FIRST EPSS](https://www.first.org/epss/) | prawdopodobieństwo exploitacji |

Agent (`claude-opus-5-5`) ma narzędzia do tych źródeł, prompt zakazujący cytowania CVE z pamięci oraz twardy
post-check: każde CVE w odpowiedzi, którego nie zwróciło żadne narzędzie, jest oznaczane ostrzeżeniem.
Te same narzędzia udostępnia [serwer MCP](#serwer-mcp) – wtedy agentem jest Claude Code, Claude Desktop,
Codex lub Twój własny agent, bez osobnego klucza API.

## Instalacja

macOS / Linux:

```bash
git clone https://github.com/zember/cvescout.git && cd cvescout
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
```

Wymaga Pythona 3.11 lub nowszego.

Windows (cmd):

```bat
git clone https://github.com/zember/cvescout.git && cd cvescout
python -m venv .venv
.venv\Scripts\pip install -e .[dev]
```

Klucze (wszystkie opcjonalne poza `ANTHROPIC_API_KEY` dla `ask`); w cmd zamiast `export` użyj `set` (lub `setx` na stałe):

```bash
export NVD_API_KEY=...        # 50 zamiast 5 zapytań / 30 s: https://nvd.nist.gov/developers/request-an-api-key
export GITHUB_TOKEN=...       # 5000 zamiast 60 zapytań / h do GHSA, np. $(gh auth token)
export ANTHROPIC_API_KEY=...  # tylko dla `cvescout ask` (albo `ant auth login`); serwer MCP go nie potrzebuje
```

## Uruchamianie bez `activate`

- **Windows:** w katalogu projektu jest `cvescout.cmd`. Uruchom `C:\sciezka\do\cvescout\cvescout.cmd feed --days 2`
  albo dodaj katalog projektu do zmiennej PATH – wtedy w dowolnym oknie cmd działa samo `cvescout feed --days 2`.
- **macOS / Linux:** `ln -s "$PWD/.venv/bin/cvescout" ~/.local/bin/cvescout` (katalog `~/.local/bin` musi być w PATH).
- **Dowolny system:** `pipx install -e .` instaluje `cvescout` globalnie w osobnym środowisku.

## Użycie

```bash
cvescout feed --days 2                               # CVE z ostatnich 48 h, najnowsze pierwsze
cvescout feed --days 7 --severity CRITICAL --enrich  # krytyczne z tygodnia + EPSS/KEV/ryzyko
cvescout feed --days 7 --sort risk                   # tydzień, najpilniejsze do załatania pierwsze
cvescout feed --days 30 --keyword fortinet
cvescout feed --days 30 --kev                        # dodane do CISA KEV w ostatnim miesiącu
cvescout feed --days 1 --json
```

### Wynik: dla ludzi czy dla agentów

| Tryb | Dla kogo | Co zawiera |
|---|---|---|
| `cvescout feed`, `cvescout cpe` | człowiek | tabela: data, ID, CVSS, znaczniki `RCE`/`PoC`/`EXPLOITED`, opis skrócony do 100 znaków |
| `cvescout feed --json`, `cvescout cpe --json` | skrypty, inne agenty, pipeline'y | pełne dane: cały opis, CWE, wektor CVSS, linki, `exploit_refs`, `affected_products`, EPSS/KEV (z `--enrich`) |
| `cvescout ask` | człowiek | odpowiedź agenta Claude w języku pytania |
| `cvescout mcp` | agenty (Claude Code, Claude Desktop, inne klienty MCP) | narzędzia zwracające JSON, jak w `ask` |

Tabela może się zmieniać i ucina dane – programy powinny czytać `--json`. Błędy trafiają na stderr, a kod wyjścia wynosi 1,
więc skrypt może łatwo wykryć niepowodzenie. Agent wbudowany w `ask` nie czyta tabeli – jego narzędzia dostają JSON bezpośrednio.

### Filtry

| Opcja | Znaczenie |
|---|---|
| `--min-score 8` | CVSS ≥ 8 |
| `--severity HIGH` | kategoria ważności co najmniej HIGH (≥ 7.0) |
| `--rce` | prawdopodobne zdalne wykonanie kodu (heurystyka: CWE wstrzyknięcia kodu/poleceń lub opis, wektor sieciowy `AV:N`, bez XSS) |
| `--poc` | znany publiczny exploit (PoC) lub aktywna exploitacja |
| `--any` | wystarczy **jeden** z powyższych warunków (domyślnie muszą być spełnione **wszystkie**) |
| `--since 2020-01-01` | od daty zamiast `--days` |
| `--keyword X` | słowo w opisie; powtórzone = „albo” |
| `--cpe vendor:product` | dokładny produkt w NVD, np. `haxx:curl`, `nodejs:node.js`, `o:linux:linux_kernel`; powtórzone = „albo”. Nazwę znajdzie `cvescout cpe` |

```bash
cvescout feed --days 7 --rce --min-score 8                  # RCE i CVSS >= 8
cvescout feed --days 7 --rce --min-score 8 --any            # RCE albo CVSS >= 8
cvescout feed --days 7 --min-score 8 --poc                  # CVSS >= 8 z publicznym exploitem
cvescout feed --since 2020-01-01 --cpe nodejs:node.js --cpe haxx:curl --rce          # RCE w Node.js albo curl od 2020
cvescout feed --since 2020-01-01 --keyword node.js --keyword curl --rce --limit 100  # szerzej, po słowach z opisu
```

Kolumna po ocenie pokazuje `RCE`, `PoC` (exploit publiczny) lub `EXPLOITED` (aktywnie wykorzystywana).

- NVD przyjmuje zakres dat do 120 dni. Dłuższy zakres (`--since`) wymaga `--keyword` albo `--cpe` – wtedy pobierana
  jest cała historia produktu i przycinana lokalnie.
- `--cpe` jest dokładniejsze niż `--keyword`: zwraca tylko CVE, w których NVD oznaczył produkt jako **podatny**
  (pomija np. aplikacje, które jedynie „działają na” Linuksie). Obejmuje jednak tylko CVE już przeanalizowane przez NVD –
  to trwa od kilku dni do tygodni, więc dla najświeższych CVE użyj `--keyword`.
- `--poc` korzysta z linków oznaczonych przez NVD jako „Exploit”, oceny CISA SSVC, dojrzałości exploita w CVSS v4 i CISA KEV.
  Brak oznaczenia nie znaczy, że exploita nie ma.
- `--rce` to heurystyka – traktuj wynik jako „prawdopodobne RCE” i sprawdzaj opis.
- CVE odrzucone (REJECTED: duplikaty, numery nadane przez pomyłkę, zgłoszenia, które nie okazały się podatnością) są pomijane.
  `get_cve_details` dla pojedynczego CVE nadal pokazuje status odrzucenia.

### Wynik ryzyka: co łatać najpierw

```bash
cvescout feed --days 7 --sort risk --limit 20                  # tydzień, najpilniejsze pierwsze
cvescout feed --cvelist --days 3 --sort risk --keyword php
cvescout feed --ghsa --days 30 --ecosystem npm --sort risk
```

`--sort risk` dodaje EPSS i KEV, ocenia **wszystkie** pasujące CVE (nie tylko najnowsze `--limit`) i sortuje je wg priorytetu.
`--enrich` dodaje ten sam wynik bez zmiany kolejności. W `--json` każde CVE ma pole
`risk: {score, priority, factors}`, a `factors` wyjaśnia ocenę (np. `actively exploited (CISA KEV)`, `EPSS 34.00%`, `CVSS 9.8`).

| Priorytet | Kiedy |
|---|---|
| `critical` | aktywnie wykorzystywana (CISA KEV, SSVC „active”, CVSS v4 `E:A`) |
| `high` | publiczny exploit lub EPSS ≥ 10% przy CVSS ≥ 7 (lub nieznanym), albo prawdopodobne RCE z CVSS ≥ 9 |
| `medium` | publiczny exploit lub EPSS ≥ 10% (przy niższym CVSS), albo CVSS ≥ 9, albo CVSS ≥ 7 razem z prawdopodobnym RCE **lub** EPSS ≥ 1% |
| `low` | pozostałe, m.in. CVSS 7–8.9 bez RCE, bez exploita i z EPSS < 1% |

Do `medium` wystarczy RCE **albo** EPSS ≥ 1%. Żeby zobaczyć tylko RCE, dodaj filtr: `cvescout feed --days 7 --sort risk --rce`.

`score` (0–100) porządkuje CVE w obrębie priorytetu: 50% zagrożenie (wykorzystywana 1.0, PoC 0.7, EPSS przeskalowany tak,
że 10% liczy się jak PoC) + 40% CVSS + 10% prawdopodobne RCE. Zagrożenie waży najwięcej, bo większość CVE – nawet
krytycznych – nigdy nie jest wykorzystywana. To heurystyka cvescout, nie oficjalna ocena; świeże CVE nie mają jeszcze EPSS
(`no EPSS yet`), więc ich wynik opiera się na CVSS i znanych exploitach.

### Wersje podatne podane przez producenta

Pole `affected` (CVE List, `get_cve_details`) pokazuje wersje zgłoszone przez producenta (CNA), a `default_status` –
co producent mówi o pozostałych wersjach (`affected`, `unaffected`, `unknown` lub brak).
**Producenci zwykle podają tylko wspierane gałęzie.** Przykład: CVE-2026-109618 w PHP wymienia 8.2–8.5 z
`default_status: unaffected`, choć starsze, niewspierane wersje (np. 7.x) mogą mieć ten sam błąd – po prostu nikt ich
nie sprawdzał i nie dostaną poprawki. Brak wersji na liście nie znaczy, że jest bezpieczna; agent i serwer MCP mają to
w instrukcjach i dostają tę uwagę w polu `affected_note`.

### Nazwy CPE: `cvescout cpe`

Nazwa w CPE ma postać `producent:produkt`, a producent często różni się od potocznej nazwy
(curl to `haxx:curl` – od Haxx AB, firmy autora curl). `cvescout cpe` wyszukuje ją w słowniku CPE NVD:

```
$ cvescout cpe nginx
CPE products for 'nginx':
  f5:nginx                       582 ver.  F5 NGINX
  nginx:nginx                    543 ver.  Nginx  [deprecated -> f5:nginx]
  igor_sysoev:nginx              383 ver.  Nginx  [deprecated -> nginx:nginx]
  ...
Use: cvescout feed --cpe f5:nginx --since 2020-01-01
```

Najpierw są produkty o pasującej nazwie, potem pozostałe. Przy wycofanych nazwach widać, czym je zastąpiono.
Systemy operacyjne mają prefiks `o:` (np. `o:linux:linux_kernel`), sprzęt `h:`.

### CVE List (CVEProject/cvelistV5)

```bash
cvescout feed --cvelist --days 1                          # wszystko z ostatnich 24 h, bez limitów NVD
cvescout feed --cvelist --days 7 --rce --min-score 8      # te same filtry co dla NVD
cvescout feed --cvelist --days 3 --keyword nginx --json   # słowo w opisie, tytule, nazwie producenta lub produktu
cvescout feed --cvelist --days 7 --url nodejs.org/en/blog/vulnerability   # CVE, do których linkuje biuletyn Node.js
```

`--url` dopasowuje fragment linku w referencjach CVE. Najlepiej podać stronę biuletynów bezpieczeństwa producenta: znajdzie
wtedy także CVE zgłoszone dla **biblioteki dołączonej do produktu**. Przykład: CVE-2026-111497 zgłosił Google dla Brotli –
w opisie nie ma słowa „Node.js”, NVD jeszcze nie przypisał CPE, a jedynym śladem jest link do biuletynu Node.js.
`--keyword node.js` i `--cpe nodejs:node.js` go nie znajdą, `--url nodejs.org/en/blog/vulnerability` – tak.

`--cvelist` czyta oficjalną listę CVE zamiast NVD: dzienne paczki zmian z
[GitHub Releases](https://github.com/CVEProject/cvelistV5/releases) (kilka MB na dzień) uzupełnione indeksem `deltaLog.json`.

- **Szybciej:** tydzień danych pobiera się w kilka sekund, bez limitu 5 zapytań / 30 s; CVE pojawia się tu ok. godzinę przed NVD.
- **Tylko 30 dni wstecz.** Dla dłuższych zakresów (`--since 2020-01-01`) użyj NVD.
- **Dane od CNA** (producenta lub innego wydawcy CVE) oraz CISA Vulnrichment (SSVC, KEV), bez analizy NVD:
  ocena CVSS czasem się różni, a `--cpe` działa tylko, gdy wydawca podał CPE – dla CVE List lepiej użyć `--keyword`.
- W `--json` każde CVE ma pole `affected`: producent, produkt i podatne wersje (np. `1.0 - <1.4`).
- `get_cve_details` (agent i MCP) dokłada `affected` z CVE List do danych NVD, a gdy NVD nie działa
  lub jeszcze nie ma danego CVE, zwraca rekord z CVE List.

### GitHub Advisory Database

```bash
cvescout feed --ghsa --days 7 --ecosystem npm --severity HIGH   # porady dla pakietów npm
cvescout feed --ghsa --days 30 --package django --rce
```

Porady GitHub „reviewed” (domyślne) pojawiają się z opóźnieniem względem NVD, bo GitHub je ręcznie weryfikuje;
`--unreviewed` dokłada nieprzejrzane, zwykle kopie wpisów z NVD bez danych o pakietach.
Dla `--ghsa` zwracanych jest najwyżej 100 najnowszych porad na zapytanie, więc długie zakresy (`--since`) są niepełne.

### Agent

```bash
cvescout ask -v "Jakie krytyczne CVE pojawiły się w ostatnich 3 dniach?"
cvescout ask "Pokaż RCE w Node.js albo curl od 2020 z publicznym exploitem"
```

Agent sam dobiera filtry (RCE, próg CVSS, PoC, produkty, daty), w razie potrzeby wyszukuje nazwy CPE
i podaje, które filtry zastosował.

Długie zakresy dla dużych produktów (np. jądro Linux od 2020) wymagają wielu zapytań do NVD –
bez `NVD_API_KEY` trwa to kilka minut.

## Alerty o nowych CVE: `cvescout watch`

`cvescout watch` sprawdza nowe CVE dla wybranych produktów, ocenia je [wynikiem ryzyka](#wynik-ryzyka-co-łatać-najpierw)
i zgłasza każde CVE **raz** – ponownie tylko wtedy, gdy jego priorytet wzrośnie (np. CISA doda je do KEV).
**Nic nie uruchamia się samo:** każde `watch run` to jedno sprawdzenie; cykliczne uruchamianie trzeba włączyć samemu.

```bash
cvescout watch init             # tworzy przykładową konfigurację
cvescout watch run --dry-run    # pokazuje alerty bez zapisywania i wysyłania
cvescout watch run              # sprawdza, zapisuje stan, wysyła alerty
cvescout watch list             # wcześniejsze alerty
cvescout watch schedule         # wypisuje linię dla cron / Harmonogramu zadań (nic nie instaluje)
```

Konfiguracja: `~/.config/cvescout/watch.toml` (Windows: `%APPDATA%\cvescout\watch.toml`) albo dowolny plik przez `--config`.
Stan (SQLite) leży obok, w `watch.db`.

```toml
source = "cvelist"        # "cvelist" (świeże, do 30 dni wstecz) albo "nvd"
min_priority = "high"     # critical, high, medium albo low
initial_days = 7          # jak daleko wstecz patrzy pierwsze uruchomienie

[[watch]]
name = "curl"
keywords = ["curl"]

[[watch]]
name = "Node.js"
cpes = ["nodejs:node.js"]
urls = ["nodejs.org/en/blog/vulnerability"]   # zawsze szukane w CVE List
source = "nvd"            # nadpisanie dla jednego produktu (dotyczy keywords i cpes)
min_priority = "medium"

[notify]
webhook_url = "https://hooks.slack.com/services/..."
webhook_format = "slack"  # slack, discord albo json
```

- Wystarczy jedno dopasowanie: `keywords`, `cpes` albo `urls`.
- `keywords` są szerokie: `node.js` pasuje do każdego „… is a Node.js CMS”. Dla takich produktów użyj `cpes`
  (nazwę znajdzie `cvescout cpe`) i `source = "nvd"` – CVE List ma CPE tylko od części producentów.
  NVD przypisuje CPE z opóźnieniem kilku dni, za to bez fałszywych trafień.
- `urls` (fragment linku w referencjach, zawsze z CVE List) łapie CVE od razu i także w bibliotekach dołączonych do
  produktu – np. biuletyn Node.js linkuje CVE w Brotli. W tygodniu 19–26.10 tylko `urls` znalazło 10 CVE Node.js,
  bo NVD nie przypisał im jeszcze CPE.
- Każde uruchomienie zaczyna od czasu poprzedniego (z godzinnym zapasem), a CVE z ostatnich 30 dni ocenia od nowa
  (EPSS i KEV zmieniają się po publikacji), więc alert przyjdzie także dla starszego CVE, które właśnie trafiło do KEV.
- Alerty zawsze trafiają na stdout (`--json` dla skryptów), a z `webhook_url` także na webhook. Jeśli webhook nie odpowie,
  alerty nie są oznaczane jako wysłane i przyjdą przy następnym uruchomieniu.
- Niektórzy producenci (np. curl) nie podają CVSS – do czasu oceny przez NVD wynik ryzyka liczy brak CVSS jako 5.0.

### Włączenie cyklicznego sprawdzania

`cvescout watch schedule` wypisuje gotowe polecenie z właściwymi ścieżkami. Dla macOS / Linux (cron, co godzinę):

```bash
crontab -e
# dopisz:
0 * * * * "/sciezka/do/cvescout/.venv/bin/cvescout" watch run >> "$HOME/.config/cvescout/watch.log" 2>&1
```

Windows (cmd, Harmonogram zadań, co godzinę):

```bat
schtasks /Create /SC HOURLY /TN cvescout-watch /TR "\"C:\sciezka\do\cvescout\.venv\Scripts\cvescout.exe\" watch run"
schtasks /Delete /TN cvescout-watch
```

Wyłączenie: usuń linię z `crontab -e` albo zadanie `cvescout-watch`.

## Serwer MCP

`cvescout mcp` uruchamia serwer [MCP](https://modelcontextprotocol.io) (stdio) z tymi samymi narzędziami co agent `ask`:
`get_current_datetime`, `search_recent_cves` (NVD lub `source="cvelist"`), `search_github_advisories`,
`find_cpe_name`, `get_cve_details`, `get_recent_exploited`. Serwer nie wywołuje modelu, więc nie potrzebuje `ANTHROPIC_API_KEY` –
pytania obsługuje klient (np. Claude Code w ramach Twojej subskrypcji). Instrukcje serwera zakazują klientowi cytowania CVE z pamięci;
twardego post-checku z `ask` tu nie ma, bo odpowiedź pisze klient.

**Claude Code** (dla wszystkich projektów; nowa sesja zobaczy narzędzia `mcp__cvescout__*`):

```bash
claude mcp add --scope user cvescout -- "$PWD/.venv/bin/cvescout" mcp
```

```bat
claude mcp add --scope user cvescout -- C:\sciezka\do\cvescout\.venv\Scripts\cvescout.exe mcp
```

**Claude Desktop** – w `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`,
Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "cvescout": {
      "command": "/Users/ty/dev/cvescout/.venv/bin/cvescout",
      "args": ["mcp"]
    }
  }
}
```

Na Windows `"command": "C:\\sciezka\\do\\cvescout\\.venv\\Scripts\\cvescout.exe"`. Klucze `NVD_API_KEY` i `GITHUB_TOKEN`
można przekazać w polu `"env"` tej samej sekcji (albo `claude mcp add -e NVD_API_KEY=...`).

**OpenAI Codex CLI:**

```bash
codex mcp add cvescout -- "$PWD/.venv/bin/cvescout" mcp
```

```bat
codex mcp add cvescout -- C:\sciezka\do\cvescout\.venv\Scripts\cvescout.exe mcp
```

Klucze przekażesz przez `--env NVD_API_KEY=...`. Długie zapytania do NVD (duże produkty z kilku lat, bez `NVD_API_KEY`)
mogą trwać minuty, dłużej niż domyślny limit czasu narzędzia w Codexie, więc wydłuż go w `~/.codex/config.toml`:

```toml
[mcp_servers.cvescout]
command = "/Users/ty/dev/cvescout/.venv/bin/cvescout"
args = ["mcp"]
tool_timeout_sec = 300
```

Serwer działa z każdym klientem MCP obsługującym stdio; sprawdzony z wersjami protokołu od 2025-03-26 do bieżącej.
To, jak ściśle klient trzyma się instrukcji serwera (bez CVE z pamięci), zależy od klienta.

**Własny agent (Python):**

```python
from mcp import Client, StdioServerParameters

async with Client(StdioServerParameters(command=".venv/bin/cvescout", args=["mcp"])) as client:
    result = await client.call_tool("search_recent_cves", {"days": 1, "source": "cvelist", "rce_only": True})
    print(result.content[0].text)  # JSON
```

## Bezpieczeństwo

- Opisy, tytuły i referencje CVE piszą osoby trzecie. cvescout usuwa z nich znaki sterujące terminala, a instrukcje agenta
  i serwera MCP każą modelowi traktować je jako dane, nigdy jako polecenia. Jeśli przekazujesz wynik `--json` do własnego
  modelu językowego, zrób to samo.
- cvescout tylko czyta publiczne dane; jedyne, co gdziekolwiek wysyła, to opcjonalny webhook `watch` pod skonfigurowany adres.
- Podatność w samym cvescout zgłoś zgodnie z [SECURITY.md](SECURITY.md).

## Testy

```bash
.venv/bin/pytest
```

## Licencja

[MIT](LICENSE)
