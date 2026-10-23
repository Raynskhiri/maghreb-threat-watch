# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report privately through GitHub: **Security** tab, then **Report a vulnerability**,
or email **skhirirayen@outlook.com** with "SECURITY: maghreb-threat-watch" in the subject.

Include what you found, how to reproduce it, and the impact you expect.
I reply within 3 working days and will credit you in the fix unless you prefer otherwise.

## Scope

The collector, scoring and site generator in this repository, the GitHub Actions workflows, and the published dashboard at threatwatch.rayenskhiri.online. The domains listed in reports are third-party data: report abuse to the registrar or hosting provider, not here.

## How this repository is protected

- Secret scanning (gitleaks) and CodeQL run on every push and pull request.
- Dependencies are audited in CI and kept current by Dependabot.
- No credentials are stored in the repository. Secrets live in GitHub Actions secrets or in local, git-ignored files.
