import { spawnSync } from 'node:child_process';
const task = process.argv[2];
let command; let args;
if (task === 'migrate') {
  command = 'target/debug/mortise-accounts'; args = ['--migrate'];
} else if (task === 'test-postgres') {
  if (!process.env.NEON_BRANCH || process.env.NEON_BRANCH === 'production') throw new Error('Use a separate Neon integration branch for tests.');
  process.env.MORTISE_TEST_DATABASE_URL = process.env.DATABASE_URL;
  command = 'cargo'; args = ['test', '-p', 'mortise-accounts', '--features', 'postgres,client', '--test', 'postgres', '--locked', '--', '--ignored', '--nocapture'];
} else throw new Error('Unknown account task');
const result = spawnSync(command, args, { stdio: 'inherit', env: process.env });
process.exit(result.status ?? 1);
