# Claude Instructions

Project-specific instructions for Claude Code.

## Quick Reference

| Resource       | Path                                |
| -------------- | ----------------------------------- |
| Quality config | `tsconfig.json`, `vitest.config.ts` |
| Linting        | `eslint.config.js`                  |
| Mutation       | `stryker.config.js`                 |
| Architecture   | `dependency-cruiser.config.js`      |
| Audit reports  | `.claude/reports/audit-report*.md`  |
| Tasks          | `.claude/tasks/TODO.md`             |

## Before Any Task

1. Read `package.json` for scripts and targets
2. Read tool config files as needed

---

## Quality Gates

All must pass before merge:

- [ ] TypeScript (`pnpm typecheck`, strict mode, no errors)
- [ ] ESLint (`pnpm lint`, no warnings)
- [ ] Prettier (`pnpm format:check`)
- [ ] Vitest (`pnpm test:coverage`, 99% lines/statements/branches, 95% functions)
- [ ] Stryker (`pnpm mutation`, break: 100)
- [ ] dependency-cruiser (`pnpm depcruise`, 0 violations)
- [ ] Build succeeds (`pnpm build`)

---

## Core Principles

### Security First

- Cryptographic randomness only (`crypto.getRandomValues()`,
  `crypto.randomBytes()`)
- Input validation for all external data
- No eval, Function constructor, or dynamic imports from user input
- Secure defaults, explicit opt-in for permissive
- Zero runtime dependencies

### Code Quality

- Immutable patterns (readonly, Object.freeze, structuredClone)
- Type safety (strict TypeScript, no `any`)
- Module boundaries (explicit exports via `src/index.ts`)
- 100% test coverage + 100% mutation score

### No Suppressions

Suppressions are the last resort. If unavoidable:

- Document why no alternative exists
- Verify no security implication
- Add justification in code/config

---

## Commit Conventions

Format: `<type>(<scope>): <description>`

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`

All commits must be GPG-signed.

---

## Language

- **English always**: Code, documentation, commits, technical content
