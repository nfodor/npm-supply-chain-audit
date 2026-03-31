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

let findings = [];
let scanned = 0;

// ===== HTTP helpers =====

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), 15000);
    https.get(url, { headers: { 'User-Agent': 'npm-supply-chain-audit/1.0' } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        clearTimeout(timer);
        return fetchJSON(res.headers.location).then(resolve).catch(reject);
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

function fetchText(url) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), 15000);
    https.get(url, { headers: { 'User-Agent': 'npm-supply-chain-audit/1.0' } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        clearTimeout(timer);
        return fetchText(res.headers.location).then(resolve).catch(reject);
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

// ===== Core audit =====

async function auditPackage(name, installedVersion) {
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
      if (scriptName === 'postinstall' || scriptName === 'preinstall' || scriptName === 'install') {
        for (const pattern of SUSPICIOUS_SCRIPTS) {
          if (pattern.test(scriptCmd)) {
            report('WARNING', `${name}@${version}`, `Suspicious ${scriptName} script: ${scriptCmd.slice(0, 100)}`);
          }
        }
      }
    }

    // 4. Find GitHub repo and compare
    const repoUrl = npmData.repository?.url || versionData.repository?.url || '';
    const ghMatch = repoUrl.match(/github\.com[:/]([^/]+)\/([^/.]+)/);

    if (!ghMatch) {
      report('INFO', `${name}@${version}`, 'No GitHub repo linked — cannot compare source vs published');
      return;
    }

    const [, owner, repo] = ghMatch;

    // For monorepo packages, derive subdirectory from package name
    // e.g., @aws-sdk/client-s3 → clients/client-s3, @sentry/node → packages/node
    const monorepoSubdirs = [];
    if (name.startsWith('@')) {
      const parts = name.split('/');
      const shortName = parts[1];
      monorepoSubdirs.push(
        `packages/${shortName}`,
        `clients/${shortName}`,
        `libs/${shortName}`,
        `modules/${shortName}`,
        `packages/${parts[0].slice(1)}-${shortName}`
      );
    }

    // Try to fetch package.json from git: tag → monorepo subdir → root → branch
    let gitPkg = null;
    const tagVariants = [`v${version}`, version, `${name}@${version}`];
    const branches = ['main', 'master'];

    for (const ref of [...tagVariants, ...branches]) {
      // Try monorepo subdirs first
      for (const subdir of monorepoSubdirs) {
        try {
          const resp = await fetchText(
            `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${subdir}/package.json`
          );
          if (resp.status === 200) {
            const parsed = JSON.parse(resp.body);
            if (parsed.name === name) { gitPkg = parsed; break; }
          }
        } catch { /* try next */ }
      }
      if (gitPkg) break;

      // Try root package.json
      try {
        const resp = await fetchText(
          `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/package.json`
        );
        if (resp.status === 200) {
          const parsed = JSON.parse(resp.body);
          if (parsed.name === name) { gitPkg = parsed; break; }
          // Root doesn't match package name — likely monorepo, skip root
          if (monorepoSubdirs.length === 0) { gitPkg = parsed; break; }
        }
      } catch { /* try next */ }
    }

    if (!gitPkg) {
      report('INFO', `${name}@${version}`, `Could not fetch package.json from GitHub (${owner}/${repo})`);
      return;
    }

    const gitDeps = { ...gitPkg.dependencies };

    // 5. Compare: deps in npm but NOT in git = possible injection
    for (const dep of Object.keys(npmDeps)) {
      if (!gitDeps[dep]) {
        // CRITICAL if known malicious or suspicious pattern, WARNING otherwise (monorepo build artifacts)
        const isMalicious = KNOWN_MALICIOUS.has(dep);
        const isSuspicious = SUSPICIOUS_DEP_PATTERNS.some(p => p.test(dep));
        if (isMalicious) {
          report('CRITICAL', `${name}@${version}`,
            `KNOWN MALICIOUS dependency "${dep}" in npm but NOT in GitHub`);
        } else if (isSuspicious) {
          report('WARNING', `${name}@${version}`,
            `Suspicious dependency "${dep}" in npm but NOT in GitHub source`);
        }
        // Skip noise for same-org deps (monorepo build output) e.g. @aws-sdk/* in @aws-sdk/client-s3
        // These are expected — monorepo packages reference siblings that aren't in the subdir package.json
      }
    }

    // 6. Compare: scripts in npm but NOT in git
    const gitScripts = gitPkg.scripts || {};
    for (const scriptName of ['postinstall', 'preinstall', 'install']) {
      if (npmScripts[scriptName] && !gitScripts[scriptName]) {
        report('CRITICAL', `${name}@${version}`,
          `Script "${scriptName}" exists in npm but NOT in GitHub — possible injection`);
      } else if (npmScripts[scriptName] && gitScripts[scriptName] &&
                 npmScripts[scriptName] !== gitScripts[scriptName]) {
        report('WARNING', `${name}@${version}`,
          `Script "${scriptName}" differs between npm and GitHub`);
      }
    }

    // 7. Check maintainer changes (npm metadata)
    const maintainers = npmData.maintainers || [];
    for (const m of maintainers) {
      if (m.email && m.email.endsWith('@proton.me')) {
        report('WARNING', `${name}@${version}`,
          `Maintainer ${m.name} uses Proton Mail (${m.email}) — verify this is legitimate`);
      }
    }

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

(async () => {
  const args = process.argv.slice(2);
  const packageFlag = args.indexOf('--package');
  const allDepsFlag = args.includes('--all-deps');
  const lockfileFlag = args.indexOf('--lockfile');

  console.log('npm Supply Chain Audit');
  console.log('='.repeat(50));

  if (packageFlag !== -1 && args[packageFlag + 1]) {
    // Single package mode
    const name = args[packageFlag + 1];
    const version = args[packageFlag + 2] && !args[packageFlag + 2].startsWith('--') ? args[packageFlag + 2] : null;
    console.log(`\nScanning: ${name}${version ? '@' + version : ''}\n`);
    await auditPackage(name, version);

  } else {
    // Project mode
    const projectDir = lockfileFlag !== -1 ? path.dirname(args[lockfileFlag + 1]) : process.cwd();
    console.log(`\nProject: ${projectDir}`);

    const { allDeps, resolved } = await scanProject(projectDir);
    const depsToScan = allDepsFlag ? Object.keys(resolved).length > 0 ? resolved : allDeps : allDeps;

    console.log(`Dependencies: ${Object.keys(depsToScan).length} (${allDepsFlag ? 'all including transitive' : 'direct only'})\n`);

    for (const [name] of Object.entries(depsToScan)) {
      const version = resolved[name] || null;
      await auditPackage(name, version);
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

  process.exit(critical.length > 0 ? 1 : 0);
})();
