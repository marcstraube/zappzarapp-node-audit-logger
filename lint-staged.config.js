export default {
  '*': ['pnpm exec secretlint'],

  'src/**/*.ts': ['pnpm exec prettier --write', 'pnpm exec eslint --fix --max-warnings=0'],
  'tests/**/*.ts': ['pnpm exec prettier --write', 'pnpm exec eslint --fix --max-warnings=0'],

  '**/*.md': ['pnpm exec prettier --write', 'pnpm exec markdownlint-cli2 --fix'],

  '!(pnpm-lock).json': ['pnpm exec prettier --write'],
};
