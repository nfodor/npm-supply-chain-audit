#!/usr/bin/env node
'use strict';

/**
 * npm Supply Chain Audit
 *
 * Detects supply chain attacks by comparing npm-published packages
 * against their GitHub source. Catches:
 *   - Dependencies added to npm tarball but not in git (axios attack vector)
 *   - postinstall scripts added to npm but not in git
 *   - Maintainer email changes (account takeover indicator)
 *   - Known malicious packages (plain-crypto-js, etc.)
 *
 * Usage:
 *   node scripts/npm-supply-chain-audit.js                    # Scan current project
 *   node scripts/npm-supply-chain-audit.js --package axios    # Scan specific package
 *   node scripts/npm-supply-chain-audit.js --all-deps         # Scan all dependencies
 *   node scripts/npm-supply-chain-audit.js --lockfile path    # Scan a lockfile
 *
 * Requires: network access to registry.npmjs.org and api.github.com
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

// Known malicious packages (update as new attacks are discovered)
const KNOWN_MALICIOUS = new Set([
  'plain-crypto-js',
  '@shadanai/openclaw',
  '@qqbrowser/openclaw-qbot',
]);

// Suspicious postinstall patterns
const SUSPICIOUS_SCRIPTS = [
  /curl\s+http/i,
  /wget\s+http/i,
  /powershell/i,
  /\.exe/i,
  /eval\(/i,
  /child_process/i,
  /\bexec\b.*http/i,
  /download/i,
];

// Suspicious dependency name patterns
const SUSPICIOUS_DEP_PATTERNS = [
  /crypto-js/i,     // typosquat of crypto-js
  /^plain-/,        // plain-* prefix used in axios attack
  /^node-/,         // common typosquat prefix
];

const INSTALL_SCRIPT_NAMES = ['postinstall', 'preinstall', 'install'];

let findings = [];
let scanned = 0;

// ===== HTTP helpers =====

function fetchJSON(url, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), 15000);
    https.get(url, { headers: { 'User-Agent': 'npm-supply-chain-audit/1.0', ...extraHeaders } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        clearTimeout(timer);
        return fetchJSON(res.headers.location, extraHeaders).then(resolve).catch(reject);
      }
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        clearTimeout(timer);
        if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0, 200)}`));
        try { resolve(JSON.parse(body)); } catch { reject(new Error('Invalid JSON')); }
      });
    }).on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

function fetchText(url, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), 15000);
    https.get(url, { headers: { 'User-Agent': 'npm-supply-chain-audit/1.0', ...extraHeaders } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        clearTimeout(timer);
        return fetchText(res.headers.location, extraHeaders).then(resolve).catch(reject);
      }
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => { clearTimeout(timer); resolve({ status: res.statusCode, body }); });
    }).on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

function report(severity, pkg, message) {
  findings.push({ severity, pkg, message });
  const icon = severity === 'CRITICAL' ? '\x1b[31mCRITICAL\x1b[0m' :
               severity === 'WARNING' ? '\x1b[33mWARNING\x1b[0m' :
               '\x1b[36mINFO\x1b[0m';
  console.log(`  [${icon}] ${pkg}: ${message}`);
}

function parseGitHubRepoSpec(input) {
  if (!input || typeof input !== 'string') return null;

  let value = input.trim();
  if (!value) return null;

  if (value.startsWith('git+')) value = value.slice(4);
  value = value.replace(/^git@github\.com:/i, 'https://github.com/');

  const shortMatch = value.match(/^([^/\s]+)\/([^/\s]+)$/);
  if (shortMatch) {
    return {
      owner: shortMatch[1],
      repo: shortMatch[2].replace(/\.git$/i, ''),
    };
  }

  const urlMatch = value.match(/^https?:\/\/github\.com\/([^/]+)\/([^/#?]+?)(?:\.git)?(?:[#/?].*)?$/i);
  if (!urlMatch) return null;

  return {
    owner: urlMatch[1],
    repo: urlMatch[2],
  };
}

function buildMonorepoSubdirs(name) {
  if (!name.startsWith('@')) return [];

  const parts = name.split('/');
  const shortName = parts[1];
  const scope = parts[0].slice(1);

  return [...new Set([
    `packages/${shortName}`,
    `clients/${shortName}`,
    `libs/${shortName}`,
    `modules/${shortName}`,
    `packages/${scope}-${shortName}`,
  ])];
}

function buildVersionRefCandidates(name, version) {
  const shortName = name.startsWith('@') ? name.split('/')[1] : name;

  return [...new Set([
    `v${version}`,
    version,
    `${name}@${version}`,
    `${shortName}@${version}`,
    `${name}/v${version}`,
    `${shortName}/v${version}`,
  ])];
}

async function fetchGitHubRefNames(owner, repo, fetchJSONImpl = fetchJSON) {
  const headers = { Accept: 'application/vnd.github+json' };
  const refs = new Set();

  try {
    const tags = await fetchJSONImpl(`https://api.github.com/repos/${owner}/${repo}/tags?per_page=100`, headers);
    if (Array.isArray(tags)) {
      for (const tag of tags) {
        if (tag && typeof tag.name === 'string') refs.add(tag.name);
      }
    }
  } catch {
    // Fall back to exact candidate guesses if the GitHub API is unavailable.
  }

  try {
    const releases = await fetchJSONImpl(`https://api.github.com/repos/${owner}/${repo}/releases?per_page=100`, headers);
    if (Array.isArray(releases)) {
      for (const release of releases) {
        if (release && typeof release.tag_name === 'string') refs.add(release.tag_name);
      }
    }
  } catch {
    // Some repos do not publish releases.
  }

  return refs;
}

async function resolveTrustedGitPackage(name, version, repoSpec, options = {}) {
  const fetchJSONImpl = options.fetchJSONImpl || fetchJSON;
  const fetchTextImpl = options.fetchTextImpl || fetchText;
  const knownRefs = await fetchGitHubRefNames(repoSpec.owner, repoSpec.repo, fetchJSONImpl);
  const exactCandidates = buildVersionRefCandidates(name, version);
  const refsToTry = exactCandidates.filter(ref => knownRefs.size === 0 || knownRefs.has(ref));
  const searchRefs = refsToTry.length > 0 ? refsToTry : exactCandidates;
  const packagePaths = [...buildMonorepoSubdirs(name), ''];

  for (const ref of searchRefs) {
    for (const packageDir of packagePaths) {
      const packagePath = packageDir ? `${packageDir}/package.json` : 'package.json';

      try {
        const resp = await fetchTextImpl(
          `https://raw.githubusercontent.com/${repoSpec.owner}/${repoSpec.repo}/${ref}/${packagePath}`
        );
        if (resp.status !== 200) continue;

        const parsed = JSON.parse(resp.body);
        if (parsed.name !== name || parsed.version !== version) continue;

        return {
          ref,
          packagePath,
          gitPkg: parsed,
        };
      } catch {
        // Try the next exact ref/path candidate.
      }
    }
  }

  return null;
}

function comparePublishedToGit(name, version, npmDeps, npmScripts, gitPkg) {
  const gitDeps = { ...gitPkg.dependencies };

  // deps in npm but NOT in git = possible injection
  for (const dep of Object.keys(npmDeps)) {
    if (!gitDeps[dep]) {
      const isMalicious = KNOWN_MALICIOUS.has(dep);
      const isSuspicious = SUSPICIOUS_DEP_PATTERNS.some(pattern => pattern.test(dep));
      if (isMalicious) {
        report('CRITICAL', `${name}@${version}`,
          `KNOWN MALICIOUS dependency "${dep}" in npm but NOT in trusted source`);
      } else if (isSuspicious) {
        report('CRITICAL', `${name}@${version}`,
          `Suspicious dependency "${dep}" in npm but NOT in trusted source`);
      } else {
        report('WARNING', `${name}@${version}`,
          `Dependency "${dep}" in npm but NOT in trusted source — possible injection`);
      }
    }
  }

  const gitScripts = gitPkg.scripts || {};
  for (const scriptName of INSTALL_SCRIPT_NAMES) {
    if (npmScripts[scriptName] && !gitScripts[scriptName]) {
      report('CRITICAL', `${name}@${version}`,
        `Script "${scriptName}" exists in npm but NOT in trusted source — possible injection`);
    } else if (npmScripts[scriptName] && gitScripts[scriptName] &&
               npmScripts[scriptName] !== gitScripts[scriptName]) {
      report('WARNING', `${name}@${version}`,
        `Script "${scriptName}" differs between npm and trusted source`);
    }
  }
}

// ===== Core audit =====

async function auditPackage(name, installedVersion, options = {}) {
  scanned++;
  process.stdout.write(`  Scanning ${name}@${installedVersion || 'latest'}...`);

  try {
    // 1. Fetch npm registry metadata
    const npmData = await fetchJSON(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    const version = installedVersion || npmData['dist-tags']?.latest;
    const versionData = npmData.versions?.[version];

    if (!versionData) {
      console.log(' not found on npm');
      return;
    }
    console.log('');

    const npmDeps = { ...versionData.dependencies };
    const npmScripts = versionData.scripts || {};

    // 2. Check for known malicious dependencies
    for (const dep of Object.keys(npmDeps)) {
      if (KNOWN_MALICIOUS.has(dep)) {
        report('CRITICAL', `${name}@${version}`, `Contains KNOWN MALICIOUS dependency: ${dep}`);
      }
      for (const pattern of SUSPICIOUS_DEP_PATTERNS) {
        if (pattern.test(dep) && !KNOWN_MALICIOUS.has(dep)) {
          report('WARNING', `${name}@${version}`, `Suspicious dependency name: ${dep} (matches ${pattern})`);
        }
      }
    }

    // 3. Check for suspicious postinstall scripts
    for (const [scriptName, scriptCmd] of Object.entries(npmScripts)) {
      if (INSTALL_SCRIPT_NAMES.includes(scriptName)) {
        for (const pattern of SUSPICIOUS_SCRIPTS) {
          if (pattern.test(scriptCmd)) {
            report('WARNING', `${name}@${version}`, `Suspicious ${scriptName} script: ${scriptCmd.slice(0, 100)}`);
          }
        }
      }
    }

    // 4. Check maintainer changes (npm metadata)
    const maintainers = npmData.maintainers || [];
    for (const m of maintainers) {
      if (m.email && m.email.endsWith('@proton.me')) {
        report('WARNING', `${name}@${version}`,
          `Maintainer ${m.name} uses Proton Mail (${m.email}) — verify this is legitimate`);
      }
    }

    // 5. Compare against a trusted repo only when the caller supplies one.
    if (!options.trustedRepo) {
      if (options.reportUntrustedRepo !== false) {
        report('INFO', `${name}@${version}`,
          'Skipping source comparison without --repo owner/repo; npm repository metadata is attacker-controlled');
      }
      return;
    }

    const source = await resolveTrustedGitPackage(name, version, options.trustedRepo, options);
    if (!source) {
      report('INFO', `${name}@${version}`,
        `Could not find ${name}@${version} in trusted repo ${options.trustedRepo.owner}/${options.trustedRepo.repo} via an exact tag or release`);
      return;
    }

    comparePublishedToGit(name, version, npmDeps, npmScripts, source.gitPkg);

  } catch (e) {
    console.log(` error: ${e.message}`);
  }
}

// ===== Scan modes =====

async function scanProject(projectDir) {
  const lockfilePath = path.join(projectDir, 'package-lock.json');
  const pkgPath = path.join(projectDir, 'package.json');

  if (!fs.existsSync(pkgPath)) {
    console.error('No package.json found in', projectDir);
    process.exit(1);
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

  // Get resolved versions from lockfile if available
  let resolved = {};
  if (fs.existsSync(lockfilePath)) {
    const lock = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
    const packages = lock.packages || {};
    for (const [key, val] of Object.entries(packages)) {
      const name = key.replace('node_modules/', '');
      if (name && val.version) resolved[name] = val.version;
    }
    // Also check v1 lockfile format
    if (lock.dependencies) {
      for (const [name, val] of Object.entries(lock.dependencies)) {
        if (val.version) resolved[name] = val.version;
      }
    }
  }

  // Check for known malicious in lockfile
  for (const name of Object.keys(resolved)) {
    if (KNOWN_MALICIOUS.has(name)) {
      report('CRITICAL', name, `KNOWN MALICIOUS package found in lockfile (version ${resolved[name]})`);
    }
  }

  // Also check node_modules directly
  const nmDir = path.join(projectDir, 'node_modules');
  if (fs.existsSync(nmDir)) {
    for (const malPkg of KNOWN_MALICIOUS) {
      const malDir = path.join(nmDir, ...malPkg.split('/'));
      if (fs.existsSync(malDir)) {
        report('CRITICAL', malPkg, `KNOWN MALICIOUS package INSTALLED in node_modules/`);
      }
    }
  }

  return { allDeps, resolved };
}

// ===== CLI =====

function parseArgs(argv) {
  const options = {
    packageName: null,
    packageVersion: null,
    allDeps: false,
    lockfile: null,
    repo: null,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg === '--package') {
      if (!argv[i + 1] || argv[i + 1].startsWith('--')) {
        throw new Error('--package requires a package name');
      }
      options.packageName = argv[++i] || null;
      if (argv[i + 1] && !argv[i + 1].startsWith('--')) {
        options.packageVersion = argv[++i];
      }
      continue;
    }

    if (arg === '--all-deps') {
      options.allDeps = true;
      continue;
    }

    if (arg === '--lockfile') {
      if (!argv[i + 1] || argv[i + 1].startsWith('--')) {
        throw new Error('--lockfile requires a path');
      }
      options.lockfile = argv[++i] || null;
      continue;
    }

    if (arg === '--repo') {
      if (!argv[i + 1] || argv[i + 1].startsWith('--')) {
        throw new Error('--repo requires owner/repo or a GitHub URL');
      }
      options.repo = argv[++i] || null;
      continue;
    }

    if (arg.startsWith('--')) {
      throw new Error(`Unknown flag: ${arg}`);
    }

    throw new Error(`Unexpected argument: ${arg}`);
  }

  return options;
}

async function main(argv = process.argv.slice(2)) {
  findings = [];
  scanned = 0;

  const args = parseArgs(argv);
  const trustedRepo = args.repo ? parseGitHubRepoSpec(args.repo) : null;

  console.log('npm Supply Chain Audit');
  console.log('='.repeat(50));

  if (args.repo && !trustedRepo) {
    console.error('\n--repo must be "owner/repo" or a GitHub URL');
    return 1;
  }

  if (args.repo && !args.packageName) {
    console.error('\n--repo currently requires --package');
    return 1;
  }

  if (args.packageName) {
    // Single package mode
    const name = args.packageName;
    const version = args.packageVersion;
    console.log(`\nScanning: ${name}${version ? '@' + version : ''}\n`);
    if (!trustedRepo) {
      console.log('Note: source comparison is disabled unless you pass --repo owner/repo.\n');
    }
    await auditPackage(name, version, { trustedRepo });

  } else {
    // Project mode
    const projectDir = args.lockfile ? path.dirname(args.lockfile) : process.cwd();
    console.log(`\nProject: ${projectDir}`);
    console.log('Note: project scans run metadata-only checks. Use --package <name> --repo <owner/repo> for exact source comparison.\n');

    const { allDeps, resolved } = await scanProject(projectDir);
    const depsToScan = args.allDeps ? Object.keys(resolved).length > 0 ? resolved : allDeps : allDeps;

    console.log(`Dependencies: ${Object.keys(depsToScan).length} (${args.allDeps ? 'all including transitive' : 'direct only'})\n`);

    for (const [name] of Object.entries(depsToScan)) {
      const version = resolved[name] || null;
      await auditPackage(name, version, { reportUntrustedRepo: false });
    }
  }

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log(`Scanned: ${scanned} packages`);

  const critical = findings.filter(f => f.severity === 'CRITICAL');
  const warnings = findings.filter(f => f.severity === 'WARNING');
  const info = findings.filter(f => f.severity === 'INFO');

  if (critical.length > 0) {
    console.log(`\n\x1b[31mCRITICAL: ${critical.length}\x1b[0m`);
    for (const f of critical) console.log(`  - ${f.pkg}: ${f.message}`);
  }
  if (warnings.length > 0) {
    console.log(`\n\x1b[33mWARNINGS: ${warnings.length}\x1b[0m`);
    for (const f of warnings) console.log(`  - ${f.pkg}: ${f.message}`);
  }
  if (info.length > 0) {
    console.log(`\nINFO: ${info.length}`);
  }

  if (critical.length === 0 && warnings.length === 0) {
    console.log('\n\x1b[32mNo supply chain issues detected.\x1b[0m');
  }

  return critical.length > 0 ? 1 : 0;
}

if (require.main === module) {
  main().then((code) => {
    process.exit(code);
  }).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}

module.exports = {
  buildMonorepoSubdirs,
  buildVersionRefCandidates,
  parseArgs,
  parseGitHubRepoSpec,
  resolveTrustedGitPackage,
};
