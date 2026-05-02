# Contributing to @zappzarapp/audit-logger

Thank you for your interest in contributing!

## Development Setup

```bash
git clone git@github.com:marcstraube/zappzarapp-node-audit-logger.git
cd zappzarapp-node-audit-logger
make install
```

## Running Tests

```bash
make check       # Run all checks (format, lint, typecheck, test, build)
make quality      # Run all quality checks including security audit
make test         # Run only tests
make test-coverage # Run tests with coverage report
make mutation     # Run mutation testing (Stryker)
```

## Code Quality

All contributions must pass:

- ESLint (with @typescript-eslint, security, sonarjs plugins)
- Prettier formatting
- TypeScript strict type checking
- Vitest with high test coverage for new code
- Stryker mutation testing

## Commit Signing

**CRITICAL: All commits MUST be GPG-signed.**

This is enforced in CI/CD:

- GitHub Actions will fail on unsigned commits
- GitLab CI will fail on unsigned commits
- Pull requests with unsigned commits will be rejected

### Setup GPG Signing

```bash
# Generate GPG key
gpg --full-generate-key

# List keys
gpg --list-secret-keys --keyid-format=long

# Export public key
gpg --armor --export YOUR_KEY_ID

# Configure Git
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
git config --global tag.gpgSign true
```

### Add GPG key to GitHub

1. Go to <https://github.com/settings/keys>
2. Click "New GPG key"
3. Paste your public key

### Verify Signatures

```bash
# Verify commit
git verify-commit HEAD

# Verify tag
git verify-tag v1.0.0
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`feature/your-feature`)
3. Make your changes
4. **Sign all commits** with GPG
5. Run `make quality` - all checks must pass
6. Push to your fork
7. Create a Pull Request

### PR Requirements

- [ ] All commits are GPG-signed
- [ ] Tests pass (`make test`)
- [ ] Code formatting is correct (`make format-check`)
- [ ] Linting passes (`make lint`)
- [ ] Type checking passes (`make typecheck`)
- [ ] Build succeeds (`make build`)
- [ ] Mutation testing passes (`make mutation`)
- [ ] Security audit passes (`make security`)
- [ ] New features have tests
- [ ] Documentation is updated

## Release Process

Releases are **fully automated** via
[release-please](https://github.com/googleapis/release-please).

### How it works

1. Review your PR (all commits must use
   [Conventional Commits](https://www.conventionalcommits.org/))
2. Merge PR to `main` branch
3. **release-please** automatically creates/updates a Release PR with:
   - Auto-generated CHANGELOG.md from commit messages
   - Version bump in package.json
4. Review the Release PR (verify changelog, version bump, breaking changes)
5. Merge the Release PR (you must GPG-sign the merge commit)
6. **release-please** automatically creates:
   - GitHub Release
   - GPG-signed tag
   - Attaches SBOM to release

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat: add new feature` -> minor version bump (0.X.0)
- `fix: resolve bug` -> patch version bump (0.0.X)
- `security: fix vulnerability` -> patch + Security section in CHANGELOG
- `feat!: breaking change` -> major version bump (X.0.0)
- `chore:`, `docs:`, `ci:` -> no version bump (included in changelog)

### Manual Release (Emergency Only)

Only for hotfixes when automation fails:

1. Create signed tag: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
2. Push tag: `git push origin vX.Y.Z`
3. Manually update CHANGELOG.md and package.json version
4. Create GitHub Release manually

## Security Vulnerabilities

**Do not report security vulnerabilities via public issues.**

See [SECURITY.md](SECURITY.md) for responsible disclosure process.

## Questions?

Open a discussion on GitHub or reach out via <email@marcstraube.de>
