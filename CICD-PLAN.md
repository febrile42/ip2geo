# CI/CD Plan — ip2geo on Linode via GitHub Actions

## What You're Building

A pipeline where pushing code to GitHub automatically tests and deploys it — no manual FTP/SCP, no SSHing in by hand.

- **`develop` branch** → runs tests → deploys to a **staging environment** → runs smoke tests and performance checks
- **`main` branch** → runs tests → deploys to **production** → runs a final smoke test

The rule: you never push directly to `main`. You work on `develop`, let the pipeline validate it on staging, and only merge to `main` when you're satisfied. This matters for ip2geo specifically because it has regular public traffic — staging gives you a place to verify changes without risking the live site.

**The stack:** GitHub → GitHub Actions → SSH → Linode (git pull)

No Docker. No extra server processes. The only thing running on the Linode is what's already there (Apache/nginx + PHP + MariaDB). GitHub's free cloud runners do all the CI work; the Linode just receives SSH commands at the end.

---

## Concepts First (skip if you know these)

**CI (Continuous Integration):** Automated checks that run every time you push code. For ip2geo this means: PHP syntax validation, a smoke test against the live staging URL, and a performance regression check.

**CD (Continuous Deployment):** The automated step that takes code that passed CI and puts it on the server. This is the part that replaces you SSHing in and running commands manually.

**GitHub Actions:** GitHub's built-in CI/CD system. You write a YAML file describing what to do when events happen (e.g., "when someone pushes to `develop`"). GitHub runs those steps on their own infrastructure — free for public repos, free up to 2,000 minutes/month for private repos. Zero load on your Linode.

**Branch strategy:**
- `develop` — your working branch. Push here often. Maps to staging.
- `main` — the stable branch. Only updated via merge from `develop`. Maps to production.
- You never push directly to `main` for day-to-day work. A merge to `main` is a deliberate act that says "I'm ready to go live."

---

## Architecture

```
Your laptop
    │  git push origin develop
    ▼
GitHub (stores code, triggers Actions)
    │  runs .github/workflows/deploy.yml
    ▼
GitHub Actions runner (GitHub's cloud server — free)
    ├─ PHP syntax check (all .php files)
    ├─ SSH into Linode → git pull → staging dir
    ├─ Smoke test: GET staging URL → expect HTTP 200
    ├─ Functional test: POST known IPs → verify geo results
    └─ Performance test: compare staging vs production timing

    (later, when you merge develop → main)
    ├─ PHP syntax check
    ├─ SSH into Linode → git pull → production dir
    └─ Smoke test: GET production URL → expect HTTP 200

Linode
    ├─ /var/www/ip2geo/          ← production (main branch)
    └─ /var/www/ip2geo-staging/  ← staging (develop branch)
```

For a PHP app with no build step, this is the right level of complexity. The tests run on GitHub's infrastructure; the Linode just serves the deployed code and responds to the test requests.

---

## Prerequisites on the Linode

Before setting up the pipeline, confirm:

1. **Git is installed:** `git --version`
2. **Apache is running and serving `/var/www/ip2geo`:** `curl -I http://ip2geo.org` should return `200 OK`
3. **Outbound access to GitHub is available:** `ssh -T git@github.com` should return a greeting (even an auth error means the connection works)

---

## One-Time Setup — Step by Step

### Step 0: Rename `master` to `main`

Do this before creating the GitHub repo so everything starts clean.

**Locally:**
```bash
git branch -m master main
```

That's it locally. After you create the GitHub repo in Step 1 and push, `main` will be the default branch. No further action needed — the old `master` name simply ceases to exist.

> If you ever need to do this on an already-pushed repo (remote already has `master`):
> ```bash
> git branch -m master main
> git push origin main
> git push origin --delete master
> # Then go to GitHub → Settings → Branches → change default branch to main
> ```

---

### Step 1: Create the GitHub repository

1. Go to github.com → New repository
2. Name it `ip2geo`, set it **private** (credentials are gitignored, but the code reveals your DB schema and server logic — keep it private until you're comfortable)
3. Do **not** initialize with README (you already have a local repo)
4. Copy the remote URL (e.g., `git@github.com:yourusername/ip2geo.git`)

Then in your local repo:
```bash
git remote add origin git@github.com:yourusername/ip2geo.git
git push -u origin main
```

Then create and push the `develop` branch:
```bash
git checkout -b develop
git push -u origin develop
```

Going forward, `develop` is where you do your work. `main` only moves when you deliberately merge.

---

### Step 2: Create a deploy SSH key pair

This is a dedicated keypair used only for deployment — not your personal key. Generate it on your laptop (not the Linode):

```bash
ssh-keygen -t ed25519 -C "ip2geo-deploy" -f ~/.ssh/ip2geo_deploy
```

Hit enter twice (no passphrase — GitHub Actions needs to use this key non-interactively).

This creates two files:
- `~/.ssh/ip2geo_deploy` — **private key** (goes to GitHub)
- `~/.ssh/ip2geo_deploy.pub` — **public key** (goes to Linode)

---

### Step 3: Install the public key on the Linode

SSH into your Linode, then:

```bash
cat >> ~/.ssh/authorized_keys
# paste the contents of ip2geo_deploy.pub, then Ctrl+D
```

Or more cleanly:
```bash
ssh-copy-id -i ~/.ssh/ip2geo_deploy.pub shadows@your.linode.ip
```

Test it works from your laptop:
```bash
ssh -i ~/.ssh/ip2geo_deploy shadows@your.linode.ip echo "ok"
```

Should print `ok` without asking for a password.

---

### Step 4: Add the private key to GitHub Secrets

GitHub Secrets are encrypted environment variables that Actions can use without exposing them in logs.

1. Go to your GitHub repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add these secrets:

| Name | Value |
|------|-------|
| `DEPLOY_SSH_KEY` | Contents of `~/.ssh/ip2geo_deploy` (the private key — the whole thing, including `-----BEGIN...` and `-----END...` lines) |
| `DEPLOY_HOST` | `lime.febrile.net` — used for both SSH deploys and direct-origin test requests |
| `DEPLOY_USER` | `shadows` |
| `DEPLOY_PATH` | `/var/www/ip2geo` |
| `STAGING_PATH` | `/var/www/ip2geo-staging` |

> `STAGING_URL` and `PROD_URL` are **not needed** — all CI tests bypass Cloudflare by hitting `DEPLOY_HOST` directly with `Host:` headers. See [Cloudflare Considerations](#cloudflare-considerations).

---

### Step 5: Initialize the repo on the Linode

The Linode currently has the old code deployed at `/var/www/ip2geo`. You need to replace it with a git-tracked clone so future deploys can use `git pull`.

```bash
# SSH into Linode as shadows
cd /var/www
mv ip2geo ip2geo_backup          # keep the old code as a safety net
git clone git@github.com:yourusername/ip2geo.git ip2geo
```

This requires the Linode to have an SSH key authorized with GitHub. The `shadows` user has an existing key — **don't use it**; add a dedicated Linode deploy key instead:

1. On the Linode, generate a key specifically for GitHub access: `ssh-keygen -t ed25519 -C "ip2geo-linode" -f ~/.ssh/github_deploy`
2. Add the public key to GitHub: repo **Settings → Deploy keys → Add deploy key** (read-only is sufficient for `git clone`/`git pull`)
3. Tell SSH to use it for GitHub: add to `~/.ssh/config`:
   ```
   Host github.com
       IdentityFile ~/.ssh/github_deploy
   ```

**After cloning, restore config.php:**

`config.php` is gitignored and won't be in the clone. Copy it from the backup — this is a one-time step.

```bash
cp /var/www/ip2geo_backup/config.php /var/www/ip2geo/config.php
```

`config.php` will survive all future `git pull` deploys because it's gitignored — git will never touch it.

**Verify permissions:** Apache (`www-data`) needs to read the files; `shadows` owns them.
```bash
chown -R shadows:www-data /var/www/ip2geo
chmod -R 755 /var/www/ip2geo
chmod 640 /var/www/ip2geo/config.php   # tighter permissions on credentials
```

---

### Step 5b: Set up staging on the Linode

Staging is a second clone of the repo, tracked on `develop`, served from a separate directory.

**Clone the staging directory:**
```bash
cd /var/www
git clone git@github.com:yourusername/ip2geo.git ip2geo-staging
cd ip2geo-staging
git checkout develop
```

**Create its own `config.php`:**
```bash
cp /var/www/ip2geo_backup/config.php /var/www/ip2geo-staging/config.php
```

> Staging can safely point to the same MariaDB as production — ip2geo is read-only (no writes to the DB), so there's no risk of data contamination.

**Set permissions:**
```bash
chown -R shadows:www-data /var/www/ip2geo-staging
chmod -R 755 /var/www/ip2geo-staging
chmod 640 /var/www/ip2geo-staging/config.php
```

**Add a DNS A record** for `staging.ip2geo.org` pointing to the same Linode IP as `ip2geo.org`. Do this in your DNS provider's control panel — propagation is usually a few minutes.

**Add an Apache VirtualHost for `staging.ip2geo.org`:**

```apache
<VirtualHost *:80>
    ServerName staging.ip2geo.org
    DocumentRoot /var/www/ip2geo-staging
    <Directory /var/www/ip2geo-staging>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

Save this to `/etc/apache2/sites-available/staging.ip2geo.org.conf`, then enable it:
```bash
sudo a2ensite staging.ip2geo.org.conf
sudo systemctl reload apache2
```

Verify it's working before setting up the pipeline: `curl -I http://staging.ip2geo.org` should return `200 OK`.

---

### Step 6: Create the GitHub Actions workflow

In your local repo, create the directory and file:

```
.github/
  workflows/
    deploy.yml
```

The workflow handles both branches. On `develop`: lint → deploy staging → test. On `main`: lint → deploy production → smoke test.

```yaml
name: CI/CD

on:
  push:
    branches:
      - main
      - develop

jobs:

  # ── Runs on both branches ──────────────────────────────────────────────────
  lint:
    name: PHP Syntax Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check all PHP files for syntax errors
        run: find . -name "*.php" -not -path "./.git/*" | xargs -I{} php -l {}

  # ── develop → staging ─────────────────────────────────────────────────────
  deploy-staging:
    name: Deploy to Staging
    needs: lint
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    steps:
      - name: Pull develop on Linode (staging dir)
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.DEPLOY_HOST }}
          username: ${{ secrets.DEPLOY_USER }}
          key: ${{ secrets.DEPLOY_SSH_KEY }}
          script: |
            cd ${{ secrets.STAGING_PATH }}
            git pull origin develop

  test-staging:
    name: Test Staging
    needs: deploy-staging
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    steps:
      - uses: actions/checkout@v4

      # All tests hit the origin directly via lime.febrile.net (not proxied by Cloudflare).
      # The Host header tells Apache which VirtualHost to serve.
      # This ensures GET results reflect live PHP health and timing reflects actual DB performance.

      - name: Smoke test — staging origin returns HTTP 200
        run: |
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Host: staging.ip2geo.org" \
            "http://${{ secrets.DEPLOY_HOST }}")
          if [ "$STATUS" != "200" ]; then
            echo "Smoke test failed: HTTP $STATUS"
            exit 1
          fi
          echo "Smoke test passed: HTTP $STATUS"

      - name: Functional test — known IP lookup returns expected country
        run: |
          RESPONSE=$(curl -s -X POST \
            -H "Host: staging.ip2geo.org" \
            "http://${{ secrets.DEPLOY_HOST }}" \
            --data-urlencode "ip_list=8.8.8.8 1.1.1.1 208.67.222.222" \
            -d "submit=1")
          if echo "$RESPONSE" | grep -qiE "United States|>US<"; then
            echo "Functional test passed"
          else
            echo "Functional test failed: expected US geo data not found"
            exit 1
          fi

      - name: Performance test — staging vs production origin (max 25% regression)
        run: |
          PAYLOAD=$(cat .github/test-fixtures/ips.txt | tr '\n' ' ')

          # Both requests go directly to the origin, bypassing Cloudflare cache
          STAGING_TIME=$(curl -s -o /dev/null -w "%{time_total}" \
            -X POST -H "Host: staging.ip2geo.org" \
            "http://${{ secrets.DEPLOY_HOST }}" \
            --data-urlencode "ip_list=${PAYLOAD}" -d "submit=1")

          PROD_TIME=$(curl -s -o /dev/null -w "%{time_total}" \
            -X POST -H "Host: ip2geo.org" \
            "http://${{ secrets.DEPLOY_HOST }}" \
            --data-urlencode "ip_list=${PAYLOAD}" -d "submit=1")

          echo "Staging: ${STAGING_TIME}s | Production: ${PROD_TIME}s"

          FAIL=$(awk "BEGIN { print ($STAGING_TIME > $PROD_TIME * 1.25) ? 1 : 0 }")
          if [ "$FAIL" = "1" ]; then
            echo "Performance regression: staging is >25% slower than production"
            exit 1
          fi
          echo "Performance check passed"

  # ── main → production ─────────────────────────────────────────────────────
  deploy-production:
    name: Deploy to Production
    needs: lint
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Pull main on Linode (production dir)
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.DEPLOY_HOST }}
          username: ${{ secrets.DEPLOY_USER }}
          key: ${{ secrets.DEPLOY_SSH_KEY }}
          script: |
            cd ${{ secrets.DEPLOY_PATH }}
            git pull origin main

      - name: Smoke test — production origin returns HTTP 200
        run: |
          sleep 3  # brief pause for Apache to serve updated files
          # Hit origin directly (lime.febrile.net), bypassing Cloudflare cache
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Host: ip2geo.org" \
            "http://${{ secrets.DEPLOY_HOST }}")
          if [ "$STATUS" != "200" ]; then
            echo "Production smoke test failed: HTTP $STATUS"
            exit 1
          fi
          echo "Production smoke test passed"
```

This uses [appleboy/ssh-action](https://github.com/appleboy/ssh-action). No software is installed on the Linode; it only runs `git pull`.

The performance test generates two **distinct random 10,000 IP lists at runtime** using Python inline in the workflow. This is intentional:

- **10,000 IPs** matches the app's real maximum input size — a smaller fixture would underrepresent actual load
- **Two different lists** (one for staging, one for production) prevents MariaDB's buffer pool from caching results from the first query, which would make the second look artificially fast
- **No fixture file needed** — IPs are generated fresh each run, just like real users generate them

The only file needed is the workflow itself:

Commit and push:
```bash
git add .github/
git commit -m "Add GitHub Actions CI/CD workflow and test fixtures"
git push origin develop
```

---

### Step 7: Watch it run

After pushing the workflow file on `develop`:

1. Go to your GitHub repo → **Actions** tab
2. You'll see the workflow triggered — it runs lint → deploy-staging → all three tests
3. Click into it to see step-by-step logs with pass/fail for each job
4. If everything is green, staging has the clean code and tests passed

**First deploy to staging will:** put the current hygienic code on the Linode's staging directory, run the smoke test to confirm the site loads, test that 8.8.8.8 resolves to the US, and benchmark against production. Since staging and production will be running the same code initially, the performance test will trivially pass — that's expected. It becomes meaningful after you start making changes on `develop`.

**First deploy to production:** once you're satisfied with staging, merge `develop` → `main`:
```bash
git checkout main
git merge develop
git push origin main
```
The pipeline fires automatically and deploys to production.

---

## What Happens on Every Subsequent Push

**Day-to-day on `develop`:**
1. Edit code locally on the `develop` branch
2. `git add`, `git commit`, `git push origin develop`
3. Actions runs: lint → deploy staging → smoke test → functional test → performance test
4. If all green: staging has your changes, tests passed
5. Total time: ~45–60 seconds

**When you're ready to go live:**
1. `git checkout main && git merge develop && git push origin main`
2. Actions runs: lint → deploy production → smoke test
3. Total time: ~20 seconds

`config.php` is never touched on either environment. The database is never touched. No service restart needed — Apache serves the new PHP files immediately on the next request.

---

## Cloudflare Considerations

Both `ip2geo.org` and `staging.ip2geo.org` are proxied through Cloudflare (WAF, DDoS protection, caching). This creates three problems for CI tests if they hit the public URLs:

1. **Smoke tests are unreliable.** Cloudflare caches GET responses at the edge. A `200 OK` from `https://ip2geo.org` only means Cloudflare is up — the origin PHP could be broken and Cloudflare would still serve cached content.
2. **Performance tests are meaningless.** Cloudflare serves cached pages from edge nodes in under 50ms regardless of what the origin is doing. Comparing staging vs production timing through Cloudflare measures CDN geography, not PHP/MariaDB performance.
3. **WAF may block automated requests.** GitHub Actions runner IPs can look like bot traffic. Cloudflare may rate-limit or challenge them, causing intermittent test failures unrelated to code.

**Solution: test directly against the origin using `lime.febrile.net`.**

`lime.febrile.net` is a direct DNS name for the Linode — it is NOT proxied through Cloudflare. Apache is already listening on it. By hitting `http://lime.febrile.net` with a `Host:` header, the request goes straight to the PHP origin, bypassing Cloudflare entirely.

This means:
- `DEPLOY_HOST` (`lime.febrile.net`) doubles as the origin test address — no new secrets needed
- Apache's VirtualHost routing still works via the `Host` header
- GET results reflect actual origin PHP health
- Performance numbers reflect actual MariaDB query time

The workflow YAML already uses this approach (see Step 6). The public `STAGING_URL` and `PROD_URL` secrets are intentionally only used for the deploy SSH commands, not for test requests.

> **Note on HTTPS:** Direct origin requests use `http://` (port 80). Cloudflare handles TLS termination; the origin itself may only be listening on port 80. This is fine — the test is measuring PHP correctness and performance, not TLS configuration.

---

## What This Pipeline Does NOT Do

**No unit tests.** The tests above are integration/black-box tests against deployed code. There's no PHPUnit or per-function test suite. That's fine — for a PHP app of this size, integration tests catch what matters (does the whole thing work?), and PHPUnit would require Composer, a test DB, and ongoing maintenance. Add it later only if the codebase grows significantly.

**No rollback automation.** If a bad deploy reaches production, the fix is to revert locally and push — which triggers another deploy. Since the whole deploy is a `git pull`, rollback is: `git revert HEAD`, `git push origin main`. Usually under 2 minutes.

**No enforced branch protection.** GitHub branch protection rules on private repos require a paid plan (GitHub Pro/Team). The rule has been configured in the repo settings but is not enforced on the free tier. Revisit if the project moves to a paid plan or goes public.

---

## Is GitHub Actions Overkill?

Not for this use case. The main alternatives:

| Approach | Complexity | Notes |
|----------|-----------|-------|
| **GitHub Actions + SSH** (this plan) | Low | Free, no server overhead, audit log |
| Manual SSH + git pull | None | What you're doing now; works but is manual |
| Webhook listener on Linode | Low-medium | Server runs a tiny listener process; more moving parts |
| Deployer (PHP tool) | Medium | Adds dependency; overkill for one server |
| Dokku / Coolify | High | Essentially lightweight PaaS; your 1GB RAM would feel it |

GitHub Actions is the right call. It runs entirely on GitHub's infrastructure, has a clear audit trail (every deploy is logged with who pushed what commit), and the YAML file lives in the repo so the pipeline is self-documenting.

---

## Security Notes

- The deploy SSH key has shell access to your Linode. Guard the private key.
- GitHub Secrets are encrypted and never appear in logs.
- Consider restricting what the deploy key can do: if the deploy user has only read access to the webroot (and is not root), the blast radius of a compromised key is limited.
- The deploy key added to GitHub as a **Deploy Key** (repo-level) is read-only by default — that's sufficient for `git clone` on the Linode. The *Actions* secret is the private key used for SSH login, which is separate.

---

## Confirmed Configuration

All pre-flight questions resolved. Nothing left to decide before executing.

| | Value |
|---|---|
| **Production path** | `/var/www/ip2geo` |
| **Staging path** | `/var/www/ip2geo-staging` |
| **Production URL** | `https://ip2geo.org` |
| **Staging URL** | `https://staging.ip2geo.org` (new DNS A record, same Linode IP) |
| **SSH user** | `shadows` |
| **Apache user** | `www-data` (standard Ubuntu — `shadows` owns files, `www-data` reads them) |
| **Linode SSH key** | Create a new dedicated key (`~/.ssh/github_deploy`) — do not reuse the existing personal key |
| **GitHub repo** | Private. 2,000 free Actions minutes/month is more than sufficient for this pipeline. |

**One remaining unknown:** your Linode's IP address — needed for the `DEPLOY_HOST` secret and the `staging.ip2geo.org` DNS record. SSH alias is `lime`; run `ssh lime "curl -s ifconfig.me"` to retrieve the IP if needed.
