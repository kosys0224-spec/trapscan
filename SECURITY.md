# Security policy

## Scope

trapscan is a static scanner. It never executes code from the repository it scans and never makes network requests (the only exception is `trapscan clone`, which invokes your local `git`). Security issues we care about:

- A crafted repository that makes trapscan crash, hang (regex catastrophic backtracking), or write outside the temporary directory when scanning an archive.
- A way to make trapscan *execute* content from the scanned repository.
- Bypasses of a rule that are cheap and generic (not "I obfuscated harder" - that is expected and documented in the README).

False positives and ordinary bugs are not security issues; please open a normal issue for those.

## Reporting

Please report security issues privately through GitHub's **"Report a vulnerability"** button on the Security tab of this repository (private vulnerability reporting). If that is unavailable, open an issue titled "security contact request" without details and a maintainer will reply with a private channel.

You can expect an acknowledgement within 7 days. Fixes are released as patch versions; reporters are credited in the changelog unless they prefer otherwise.

## Supported versions

Only the latest release receives fixes.
