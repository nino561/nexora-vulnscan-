# Nexora VulnScan v3 — FortWatch-inspired, original site

This release adds an original, responsive marketing landing page at `/` and retains the functional five-module dashboard at `/dashboard.html`. The palette is white `#FFFFFF`, purple `#7C3AED`, charcoal `#111827`. It is **not** a copy of FortWatch's source code, assets, or branding.

## What is implemented

- Responsive marketing site with hero product preview, feature cards, five scanner categories, workflow and responsible-use section.
- Dashboard with five module views. **Only the allowlisted Nmap network engine is currently integrated**. The other four integrations are explicitly marked planned, not faked.
- Python FastAPI backend with audit logs, integrity hashes and JSON exports from the previous tested starter. This new version was checked for syntax, but has not been end-to-end deployed.
- No Cloudflare bypass, unrestricted scanning or real university exploitation workflows. Such activities require written authorization from the owning organization; use an isolated intentionally vulnerable lab for exploitation demonstrations.

## Kali Linux development

```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap
cd nexora-vulnscan-v3/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env
# Set a strong SCAN_API_KEY and keep ALLOWED_TARGETS=127.0.0.1 for testing.
set -a; source .env; set +a
uvicorn main:app --host 127.0.0.1 --port 8000
```

Separate terminal:

```bash
cd nexora-vulnscan-v3/frontend
python3 -m http.server 3000
```

Open `http://localhost:3000` for the landing page or `http://localhost:3000/dashboard.html` for the security dashboard. From dashboard gear/settings, connect to `http://127.0.0.1:8000` with your development API key. Authorized local test target: `127.0.0.1`.

## GitHub → Vercel

Create a repository, do not commit secrets or `.env`, push your code, then select **Add New → Project → Import GitHub repository** in Vercel. Set Root Directory to `frontend`, Framework Preset `Other`, and leave Build Command unset. Deploy to serve the static frontend. Production frontend functions will NOT access your laptop localhost API; host a separate HTTPS scanning backend with real authentication and authorization.

## Expansion plan

1. Domain ownership validation (DNS TXT or well-known token) and verified scope storage.
2. Secure authentication, quotas, rate limits, workspace separation, queued isolated workers, audit storage.
3. Web: passive HTTPS/TLS/header/DNS checks, then permissioned ZAP baseline jobs.
4. Code: GitHub App permissions + Semgrep and OSV-Scanner in sandboxed workers.
5. Containers: Trivy analysis of immutable image digests; restrict registry credentials.
6. Cloud: Checkov IaC upload and optional Prowler read-only accounts.
7. Per-scan PDF reports, honest severity scoring, remediation workflow, scheduled scans.

Important: Public university or Cloudflare-protected website scans require authorization from the owner and an agreed testing scope. A teacher assignment alone does not establish permission. No attempted origin discovery or edge-control evasion is included.
