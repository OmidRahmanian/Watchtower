# WatchTower

**Keep watch over your attack surface as it changes.**

WatchTower is a Python reconnaissance and attack surface monitoring toolkit for security researchers and bug bounty workflows. It brings recurring subdomain discovery, DNS resolution, HTTP service checks, and Nuclei scans into one workflow, with findings stored in MongoDB and notifications delivered through Discord and Telegram.

Use it to build an inventory of your targets, discover newly exposed services, and follow changes over time.

## What it does

- **Discover subdomains** with Subfinder, certificate transparency data from crt.sh, and SecurityTrails.
- **Resolve discovered names** with ShuffleDNS and wordlists, including integrations for DNSGen, Altdns, and AlterX.
- **Track HTTP services** and compare status codes, page titles, detected technologies, and response body hashes.
- **Run Nuclei checks** against newly discovered assets and integrate new template checks.
- **Send notifications** for discoveries, HTTP changes, scan results, and runtime errors.
- **Explore your inventory** through a terminal manager with searches, exports, target management, and settings.

```mermaid
flowchart LR
    A[Target domains] --> B[Subdomain discovery]
    B --> C[DNS resolution]
    C --> D[HTTP service checks]
    D --> E[Nuclei checks]
    B --> F[(MongoDB inventory)]
    C --> F
    D --> F
    B --> G[Discord / Telegram]
    D --> G
    E --> G
    F --> H[Terminal manager / exports]
```

## Requirements

WatchTower uses Python, MongoDB, and external command-line tools. Install the tools needed by the jobs you enable and make sure they are available on your `PATH`.

| Component | Purpose |
| --- | --- |
| Python 3.10+ recommended | Runs the scheduler and terminal manager |
| MongoDB at `mongodb://localhost:27017/` | Stores discovered assets and service metadata |
| Docker with Compose | Runs MongoDB using the included configuration |
| Subfinder | Subdomain discovery |
| PostgreSQL client (`psql`) | crt.sh certificate transparency queries |
| ShuffleDNS and MassDNS | DNS resolution and wordlist checks |
| ProjectDiscovery httpx | HTTP probing; this is the ProjectDiscovery CLI |
| Nuclei and Git | Scanning and template retrieval |
| DNSGen, Altdns, AlterX | Dynamic subdomain permutations |

SecurityTrails also requires an API key. DNS jobs require a resolver list at `~/.resolvers`, a static wordlist at `wordlist/static.txt`, and, for dynamic resolution, a permutation wordlist at `wordlist/gen_alt.txt`. Supply these files before enabling the corresponding jobs.

## Getting started

### 1. Install Python dependencies

```bash
git clone https://github.com/OmidRahmanian/Watchtower.git
cd Watchtower
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pymongo requests discord.py schedule colorama rich
mkdir -p files export output wordlist
```

### 2. Start MongoDB

```bash
docker compose up -d mongodb
```

If your installation provides the standalone Compose command, use `docker-compose up -d mongodb`.

### 3. Configure notifications

Create a local `.env` file with your credentials. The published scripts read environment variables directly, so load this file into your shell before running them.

One Discord webhook can serve every notification category. Separate webhooks can route categories to different channels.

```bash
DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN'
NEW_SUB_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
NEW_RES_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
HTTP_CHANGE_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
NEW_HTTP_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
NUCLEI_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
OTHER_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"

TELEGRAM_CHAT_ID='YOUR_CHAT_ID'
TELEGRAM_BOT_TOKEN='YOUR_BOT_TOKEN'
NEW_SUB_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
NEW_RES_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
HTTP_CHANGE_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
NEW_HTTP_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
NUCLEI_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
OTHER_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"

# Required when using SecurityTrails; multiple keys are comma-separated.
SECURITYTRAILS_API_KEYS='YOUR_SECURITYTRAILS_API_KEY'
```

The published `watch.py` requires all six Discord variables and all seven Telegram variables at startup, including when individual jobs are disabled. It supports using the same Telegram bot token for each category.

Load the configuration:

```bash
chmod 600 .env
set -a
source .env
set +a
```

`.env` is ignored by Git. Keep real webhook URLs, bot tokens, and API keys in that local file.

### 4. Set your targets

Replace the sample domains in `targets.json` with your own scope:

```json
{
  "example.com": {
    "report_url": "https://example.com/security",
    "out_of_scope": [
      "excluded.example.com"
    ]
  }
}
```

`targets.json` drives recurring monitoring. `starttargets.json` supplies domains for the separate initial collection script. The `out_of_scope` checks compare exact subdomain strings; they do not expand wildcard patterns.

### 5. Choose your jobs

Edit `setting.json` to enable integrations you have configured. Each recurring job has a `status`, a numeric `value`, and a `time` unit such as `hours`, `days`, or `weeks`:

```json
"subfinder": {
  "time": "hours",
  "value": "3",
  "status": "enable"
}
```

This is an entry inside the settings object. Use `"status": "disable"` for jobs with missing tools or credentials.

The published defaults schedule Subfinder, crt.sh, and SecurityTrails every three hours; DNS resolution every six hours; static wordlist resolution every three days; dynamic resolution weekly; and HTTP checks and new template checks daily.

Additional settings control notifications, HTTP change comparisons, scanning new assets, and the Nuclei command arguments.

### 6. Run WatchTower

From the project directory, with the virtual environment active and credentials loaded:

```bash
python -u watch.py
```

The scheduler waits until each job's first interval has elapsed. Starting it does not immediately run a full scan. Keep the process running to execute scheduled jobs.

For an initial collection, configure `starttargets.json` and run:

```bash
python -u start.py
```

`start.py` runs its collection pipeline immediately, including SecurityTrails, and requires that pipeline's dependencies and API key. After a successful run, it merges those targets into `targets.json`.

## Manage findings

Open the terminal manager in another shell:

```bash
source .venv/bin/activate
python manager.py
```

The menu supports exporting discovered, resolved, and HTTP assets; searching by subdomain, status code, technology, or title; querying records; editing targets; and updating settings. Exports are written to `export/`.

## Project layout

| File or directory | Role |
| --- | --- |
| `watch.py` | Recurring monitoring scheduler and notification integrations |
| `start.py` | Initial collection pipeline |
| `manager.py` | Interactive terminal manager |
| `setting.json` | Job intervals, feature switches, and scan options |
| `targets.json` | Recurring monitoring scope |
| `starttargets.json` | Initial collection scope |
| `docker-compose.yml` | MongoDB service and persistent storage |
| `wordlist/` | User-supplied DNS wordlists |
| `files/` | Working files |
| `export/` | Exported inventories |
| `data/` | Local MongoDB storage and backup paths |

## Operational notes

WatchTower is an early version that coordinates external tools. Check each enabled integration with your installed tool versions before relying on unattended monitoring.

- A startup `KeyError` naming a webhook or Telegram variable means the environment configuration has not been fully exported.
- MongoDB must be reachable at `localhost:27017` before collection or inventory queries run.
- `SECURITYTRAILS_API_KEYS is not configured` means the SecurityTrails job needs credentials or should be disabled in the recurring scheduler.
- Some error recovery commands in `watch.py` use Linux services. On macOS, manage MongoDB through Docker or your own service setup.
- Run commands from the repository directory because the scripts use relative paths for settings and working files.

Use WatchTower within the scope of systems you own or are authorized to assess.
