# npm Supply Chain Audit

Detects supply chain attacks on npm packages by comparing what's published to npm against the GitHub source. Built in response to the [axios compromise of March 31, 2026](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan).

## What it detects

- **Dependency injection** — dependencies in the npm tarball that don't exist in the GitHub source (the exact axios attack vector)
- **Script injection** — postinstall/preinstall scripts in npm that don't exist in git
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
```

### Scan all dependencies (including transitive)

```bash
node index.js --all-deps
```

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
4. Finds the GitHub repo from npm metadata
5. Fetches `package.json` from the corresponding git tag (handles monorepos by checking subdirectories)
6. Diffs dependencies: anything in npm but not in git is flagged
7. Diffs scripts: postinstall/preinstall in npm but not in git is flagged
8. Checks maintainer emails for suspicious providers

## Why this works

The axios attack worked because the attacker had npm publish access (hijacked maintainer account) and added `plain-crypto-js` as a dependency in the npm-published `package.json` — but never committed it to GitHub.

npm publishes whatever tarball you upload. It doesn't verify against the git repo. This tool does that verification.

## CI integration

```yaml
# GitHub Actions
- name: Supply chain audit
  run: node npm-supply-chain-audit/index.js
  # Exits 1 if CRITICAL findings
```

## Limitations

- Requires network access to npmjs.org and github.com
- Monorepo packages may not be found if the subdirectory structure is non-standard
- Cannot detect attacks where the GitHub repo itself is compromised
- Rate limited by GitHub's anonymous API (60 req/hour) — use a token for large scans

## Background

On March 31, 2026, the axios npm package (100M+ weekly downloads) was compromised via maintainer account hijacking. The attacker published versions 1.14.1 and 0.30.4 containing a hidden dependency (`plain-crypto-js`) that deployed a cross-platform remote access trojan within 2 seconds of `npm install`.

The attack was possible because npm has no verification between what's in git and what's published. This tool fills that gap.

## License

MIT
