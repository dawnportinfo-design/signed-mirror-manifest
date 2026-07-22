import { spawnSync } from 'node:child_process';

const npmCli = process.env.npm_execpath;

if (!npmCli) {
  console.error('npm_execpath is not available. Run this script through npm.');
  process.exit(1);
}

for (const script of ['typecheck', 'validate:examples', 'test', 'build']) {
  const result = spawnSync(process.execPath, [npmCli, 'run', script], {
    stdio: 'inherit',
    shell: false,
  });

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

const smoke = spawnSync(process.execPath, ['scripts/smoke-cli.mjs'], {
  stdio: 'inherit',
  shell: false,
});

if (smoke.status !== 0) {
  process.exit(smoke.status ?? 1);
}
