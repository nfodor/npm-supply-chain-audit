const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildVersionRefCandidates,
  parseArgs,
  parseGitHubRepoSpec,
  resolveTrustedGitPackage,
} = require('../index.js');

test('parseGitHubRepoSpec accepts owner/repo and GitHub URLs', () => {
  assert.deepEqual(parseGitHubRepoSpec('axios/axios'), { owner: 'axios', repo: 'axios' });
  assert.deepEqual(
    parseGitHubRepoSpec('git+https://github.com/axios/axios.git'),
    { owner: 'axios', repo: 'axios' }
  );
  assert.deepEqual(
    parseGitHubRepoSpec('git@github.com:axios/axios.git'),
    { owner: 'axios', repo: 'axios' }
  );
  assert.equal(parseGitHubRepoSpec('https://gitlab.com/axios/axios'), null);
});

test('buildVersionRefCandidates stays version-scoped', () => {
  assert.deepEqual(
    buildVersionRefCandidates('@scope/pkg', '1.2.3'),
    ['v1.2.3', '1.2.3', '@scope/pkg@1.2.3', 'pkg@1.2.3', '@scope/pkg/v1.2.3', 'pkg/v1.2.3']
  );
});

test('parseArgs rejects flags with missing values', () => {
  assert.throws(() => parseArgs(['--package']), /--package requires a package name/);
  assert.throws(() => parseArgs(['--lockfile']), /--lockfile requires a path/);
  assert.throws(() => parseArgs(['--repo']), /--repo requires owner\/repo or a GitHub URL/);
});

test('resolveTrustedGitPackage uses exact version refs and does not fall back to branches', async () => {
  const requestedUrls = [];
  const repoSpec = { owner: 'axios', repo: 'axios' };
  const source = await resolveTrustedGitPackage('axios', '1.2.3', repoSpec, {
    fetchJSONImpl: async (url) => {
      if (url.includes('/tags?')) return [{ name: 'v1.2.3' }, { name: 'main' }];
      if (url.includes('/releases?')) return [];
      throw new Error(`unexpected URL: ${url}`);
    },
    fetchTextImpl: async (url) => {
      requestedUrls.push(url);
      if (url.includes('/v1.2.3/package.json')) {
        return {
          status: 200,
          body: JSON.stringify({ name: 'axios', version: '1.2.3', dependencies: {} }),
        };
      }
      return { status: 404, body: '' };
    },
  });

  assert.equal(source.ref, 'v1.2.3');
  assert.deepEqual(requestedUrls, [
    'https://raw.githubusercontent.com/axios/axios/v1.2.3/package.json',
  ]);
});

test('resolveTrustedGitPackage rejects package.json files with the wrong version', async () => {
  const repoSpec = { owner: 'axios', repo: 'axios' };
  const source = await resolveTrustedGitPackage('axios', '1.2.3', repoSpec, {
    fetchJSONImpl: async (url) => {
      if (url.includes('/tags?')) return [{ name: 'v1.2.3' }];
      if (url.includes('/releases?')) return [];
      throw new Error(`unexpected URL: ${url}`);
    },
    fetchTextImpl: async () => ({
      status: 200,
      body: JSON.stringify({ name: 'axios', version: '1.2.2', dependencies: {} }),
    }),
  });

  assert.equal(source, null);
});
