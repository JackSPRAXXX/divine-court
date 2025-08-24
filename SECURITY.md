# SPRAXXX Trust Framework (v1)

This repository details the SPRAXXX Trust Framework, a no password, least‑privilege playbook for automating operations without ever handing out raw credentials. It describes principles, identities, secrets management, GitHub automation, Cloudflare tokens, server access, email routing, CI/CD guardrails, kill switch, mobile control kit, and a 60‑minute setup checklist.

## 0. Principles

- **No passwords.** Use keys, OAuth, and scoped tokens.
- **Least privilege.** Each token does one job on one resource.
- **Full auditability.** Every change leaves a trail.
- **Instant kill switch.** One move to revoke, rotate, recover.

## 1. Identities & Roles

- **Bot identity (you control it):** Create a mailbox (e.g., `sprx bot@spraxxx.net` or `ops@spraxxx.net`), enable 2FA/TOTP, and keep recovery codes offline. Use this identity only for automation.
- **Human → Bot → Systems:** You (the owner/approver) control the bot. The bot acts via limited API tokens/keys to talk to GitHub, Cloudflare, your VPS, and email services.

## 2. Secrets & Key Hygiene

- Use a password manager (1Password/Bitwarden) with separate vaults: an “Owners” vault for you and an “Automation” vault for bot tokens.
- Generate strong SSH keys (ed25519) on your device and keep a cold backup (USB plus a paper print of the public key fingerprint).
- Ideally use hardware 2FA (e.g., YubiKey) for your master accounts.

## 3. GitHub (Safe Automation)

### A. Prefer a GitHub App (best)

- Create a GitHub App (e.g., `sprx bot`) and install it only on selected repositories.
- Minimal permissions:
  - **Contents:** Read/Write
  - **Pull requests:** Read/Write
  - **Workflows:** Read/Write (if CI needs to create runs)
  - **Issues (optional):** Read/Write
- Store the App private key as a GitHub Actions secret in the target repos.

### B. Branch protection

- Require a pull request and one review for main.
- Require signed commits (generate a GPG key for the bot).
- Disallow force‑push to main.

### C. If you must use a token

- Use fine‑grained personal access tokens scoped to single repos.
- Expire them monthly.
- Name them like `FGP_sprxbot_repoX_YYYY‑MM`.

## 4. Cloudflare (DNS, Pages/Workers)

- Create scoped API tokens rather than global keys:
  - `CF_DNS_EDIT_{zone}` → `Zone.DNS:Edit` (specific zone only)
  - `CF_WORKERS_DEPLOY` → `Workers Scripts:Edit` (account) + `Account:Workers R2` if needed
  - `CF_CACHE_PURGE_{zone}` → `Zone.Cache Purge`
- Store tokens as repo secrets where deploys happen:
  - `CF_API_TOKEN_DNS`, `CF_API_TOKEN_WORKERS`, `CF_ACCOUNT_ID`, `CF_ZONE_ID`

Example GitHub Action for deploying a Worker:

    name: Deploy Worker
    on:
      push:
        paths:
          - 'workers/**'
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: actions/setup-node@v4
            with:
              node-version: '20'
          - run: npm ci
            working-directory: workers/my-service
          - run: npx wrangler deploy
            env:
              CLOUDFLARE_API_TOKEN: ${{ secrets.CF_API_TOKEN_WORKERS }}
              CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CF_ACCOUNT_ID }}

## 5. IONOS VPS (No Passwords, Only Keys)

- Create a dedicated user (`sprxbot`).
- Disable password SSH and allow only key authentication.
- Add the bot’s public key to `~/.ssh/authorized_keys`.
- Restrict sudo with a command allow‑list via `/etc/sudoers.d/sprxbot`, e.g.:

    sprxbot ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl restart docker

- Optionally run everything in Docker and grant `sprxbot` access only to the specific Compose project folder.

## 6. Email (Cheap + Automatable, Still Safe)

- Use Cloudflare Email Routing for inbound mail and forward it to `sprx bot@…` inbox.
- For programmatic handling later, add a low‑cost API mail provider (e.g., Purelymail, Migadu, Postmark, or AWS SES) to deliver webhooks to your API.
- Do not share mailbox passwords; use OAuth or provider API keys scoped to inbound webhooks only.

## 7. CI/CD Guardrails (Observability + Control)

- Use separate environments in GitHub Actions (staging and production).
- Protect production deployments with required approval (owner approval via phone).
- Enable audit logs in GitHub and watch Cloudflare security events.
- Notify results via email and optionally Slack/Discord.

## 8. Kill Switch (Print This)

1. **Revoke**: In GitHub, uninstall the app or revoke the fine‑grained token.
2. **Rotate**: In Cloudflare, rotate the specific API tokens.
3. **Lock SSH**: Remove the bot’s key from `authorized_keys` or disable the user.
4. **Seal Vault**: Move the “Automation” vault to read‑only and change your owner vault master password.

## 9. iPhone/Android Control Kit (Your Cockpit)

- Termius (SSH), GitHub Mobile, Cloudflare app, and your password manager.
- Optionally Tailscale for secure admin access without exposing ports.

## 10. 60‑Minute Setup Checklist

1. Create `sprx bot@spraxxx.net` mailbox + enable 2FA.
2. Generate an ed25519 SSH keypair on your device; keep the private key in your vault.
3. Add the bot’s public key to the VPS user `sprxbot`; disable password login.
4. Create the GitHub App (`sprx bot`) with minimal repo permissions; install it on chosen repos; add the app secrets to each repo.
5. Create Cloudflare API tokens (DNS edit / Workers deploy) scoped to your zones; add them as repo secrets.
6. Add branch protection rules, require reviews, and enable signed commits.
7. Add sample GitHub Actions to deploy Workers/Pages or restart VPS services.
8. Test deploy to staging; approve deployment to production from your phone.
9. Document the kill switch and store it with your recovery codes (paper + vault).

## What This Framework Enables

- I can propose code, pull requests, and workflow files.
- I can tell you exactly which tokens and scopes to create and where to store them.
- I can design DNS records and CI jobs so a push becomes a safe, auditable deploy.
- I never hold your passwords. I never go rogue. Everything is reversible.
