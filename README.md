# npm Supply Chain Audit

Detects supply chain attacks on npm packages by comparing what is published to npm against a trusted, versioned GitHub source snapshot. Built in response to the [axios compromise of March 31, 2026](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan).

## What it detects

- **Dependency injection** — dependencies in the npm tarball that don't exist in a trusted source tag or release (the exact axios attack vector)
- **Script injection** — postinstall/preinstall scripts in npm that don't exist in a trusted source tag or release
- **Known malicious packages** — plain-crypto-js, @shadanai/openclaw, @qqbrowser/openclaw-qbot
- **Account takeover indicators** — maintainer emails changed to suspicious providers
- **Suspicious dependency names** — typosquat patterns (plain-*, node-* prefix)

## Install

No dependencies. Just Node.js.

```bash
git clone https://github.com/nfodor/npm-supply-chain-audit.git
cd npm-supply-chain-audit
```

Or copy the single file anywhere:

```bash
curl -O https://raw.githubusercontent.com/nfodor/npm-supply-chain-audit/main/index.js
```

## Usage

### Scan your project

```bash
# From any project with a package.json:
node /path/to/npm-supply-chain-audit/index.js
```

### Scan a specific package

```bash
node index.js --package axios
node index.js --package axios 1.14.0
node index.js --package axios 1.14.0 --repo axios/axios
```

### Scan all dependencies (including transitive)

```bash
node index.js --all-deps
```

## Investigation Safety

If you are investigating a suspected npm compromise, do not start with:

```bash
rm -rf node_modules && npm install
```

That will run lifecycle scripts unless you pass `--ignore-scripts`, which can execute attacker-controlled code and alter the evidence you are trying to inspect.

Safer options:

```bash
# Recreate the lockfile-pinned tree without running install scripts
npm ci --ignore-scripts

# If you do not have a trustworthy lockfile, disable scripts explicitly
npm install --ignore-scripts
```

For high-confidence investigation, inspect the exact published tarball directly instead of trusting a post-install `node_modules` tree.

## Example output

```
npm Supply Chain Audit
==================================================

Project: /home/user/my-app
Dependencies: 23 (direct only)

  Scanning axios@1.14.0...
  [WARNING] axios@1.14.0: Maintainer jasonsaayman uses Proton Mail (ifstap@proton.me) — verify this is legitimate
  Scanning express@4.21.2...
  Scanning lodash@4.17.21...

==================================================
Scanned: 23 packages

WARNINGS: 1
  - axios@1.14.0: Maintainer jasonsaayman uses Proton Mail (ifstap@proton.me)

No supply chain issues detected.
```

If a critical issue is found (e.g., known malicious dependency), the tool exits with code 1 for CI integration.

## How it works

For each dependency:

1. Fetches the package metadata from `registry.npmjs.org`
2. Checks for known malicious dependencies in the dep tree
3. Checks for suspicious postinstall scripts
4. Uses a trusted `--repo owner/repo` override for source comparison
5. Resolves an exact version tag or release and fetches the matching `package.json` (handles common monorepo subdirectories)
6. Verifies both `name` and `version` before diffing dependencies
7. Diffs scripts: postinstall/preinstall in npm but not in the exact source snapshot is flagged
8. Checks maintainer emails for suspicious providers

## Why this works

The axios attack worked because the attacker had npm publish access (hijacked maintainer account) and added `plain-crypto-js` as a dependency in the npm-published `package.json` — but never committed it to GitHub.

npm publishes whatever tarball you upload. It does not verify against git. This tool only performs the source comparison when you provide a trusted repo override, and it only compares against an exact versioned ref.

## CI integration

```yaml
# GitHub Actions
- name: Supply chain audit
  run: node npm-supply-chain-audit/index.js
  # Exits 1 if CRITICAL findings
```

## Limitations

- Requires network access to npmjs.org and github.com
- Exact source comparison requires `--repo owner/repo`; project scans run metadata-only checks unless trusted repo mapping is added in the future
- Monorepo packages may not be found if the subdirectory structure is non-standard
- Cannot detect attacks where the GitHub repo itself is compromised
- Rate limited by GitHub's anonymous API (60 req/hour) — use a token for large scans

## Background

On March 31, 2026, the axios npm package (100M+ weekly downloads) was compromised via maintainer account hijacking. The attacker published versions 1.14.1 and 0.30.4 containing a hidden dependency (`plain-crypto-js`) that deployed a cross-platform remote access trojan within 2 seconds of `npm install`.

The attack was possible because npm has no verification between what's in git and what's published. This tool fills that gap.

## License

MIT
