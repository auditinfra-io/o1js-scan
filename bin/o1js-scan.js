#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const prog = path.basename(process.argv[1] || 'o1js-scan').replace(/\.js$/, '');
const pythonCandidates = process.env.O1JS_SCAN_PYTHON
  ? [process.env.O1JS_SCAN_PYTHON]
  : process.platform === 'win32'
    ? ['py', 'python']
    : ['python3', 'python'];

const env = {
  ...process.env,
  O1JS_SCAN_PROG: prog,
  PYTHONPATH: process.env.PYTHONPATH
    ? `${repoRoot}${path.delimiter}${process.env.PYTHONPATH}`
    : repoRoot,
};

let missingPython;
for (const python of pythonCandidates) {
  const result = spawnSync(python, ['-m', 'o1js_scan.cli', ...process.argv.slice(2)], {
    stdio: 'inherit',
    env,
  });

  if (result.error && result.error.code === 'ENOENT') {
    missingPython = result.error;
    continue;
  }

  if (result.error) {
    console.error(`${prog}: failed to launch ${python}: ${result.error.message}`);
    process.exit(2);
  }

  process.exit(result.status === null ? 1 : result.status);
}

console.error(`${prog}: Python was not found. Install Python 3.8+ or set O1JS_SCAN_PYTHON.`);
if (missingPython && process.env.O1JS_SCAN_DEBUG) {
  console.error(missingPython.message);
}
process.exit(2);
