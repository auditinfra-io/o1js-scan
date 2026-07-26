'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');

function run(command, args) {
  return spawnSync(command, args, { encoding: 'utf8' });
}

const o1jsHelp = run('node', ['bin/o1js-scan.js', '--help']);
assert.equal(o1jsHelp.status, 0, o1jsHelp.stderr);
assert.match(o1jsHelp.stdout, /^usage: o1js-scan/m);

const noirHelp = run('node', ['bin/noir-scan.js', '--help']);
assert.equal(noirHelp.status, 0, noirHelp.stderr);
assert.match(noirHelp.stdout, /^usage: noir-scan/m);

const cleanNoir = run('node', [
  'bin/noir-scan.js',
  'examples/noir_constrained.nr',
  '--lang',
  'noir',
  '--fail-on',
  'high',
]);
assert.equal(cleanNoir.status, 0, cleanNoir.stderr);
assert.match(cleanNoir.stderr, /noir-scan: no findings/);
