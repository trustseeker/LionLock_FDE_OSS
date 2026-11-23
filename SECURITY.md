# Security Policy

LionLock is a deterministic gate: it scores a model response, decides ALLOW, REFRESH or BLOCK, and
keeps a verifiable record of that decision. For LionLock, a security problem is anything that makes
it give a weaker or non-repeatable decision than its documented rule, lose or alter a record without
detection, leak private data, or put something other than the tagged source on PyPI.

## Reporting a vulnerability

**Please report privately. Do not open a public issue, pull request or discussion.**

1. Go to [Report a vulnerability](https://github.com/trustseeker/LionLock_FDE_OSS/security/advisories/new)
   (the repository's **Security** tab, then **Report a vulnerability**). Only the maintainers can
   see the report.
2. Include:
   - the LionLock version (`pip show lionlock`) or the commit hash;
   - your Python version and operating system;
   - the affected component (for example `core.gating`, `logger`, `telemetry.receiver`);
   - the smallest reproduction you can give, as a script or exact commands;
   - what you expected, what happened, and the impact you see.
3. Use synthetic data only. Never include real prompts, model responses, API keys, tokens or
   personal data in a report.

If you cannot use GitHub's private reporting, open a public issue that says only that you have a
security report and need a private channel. Put no details in it.

## What happens next

- We aim to acknowledge a report within 7 days and to give a first assessment within 14 days.
  LionLock is maintained by a small team, so please allow for that.
- We keep you informed while we confirm the problem, write a test that reproduces it, and fix it.
- Fixes ship in a new release on PyPI with a [changelog](CHANGELOG.md) entry. Confirmed
  vulnerabilities are published as a
  [GitHub security advisory](https://github.com/trustseeker/LionLock_FDE_OSS/security/advisories),
  with a CVE where one applies.
- We credit reporters in the advisory unless you ask us not to.
- Please keep the details private until a fix is released or 90 days have passed, whichever comes
  first. If you need a different date, say so in the report and we will agree one.

## Supported versions

| Version | Security fixes |
| --- | --- |
| Newest 1.0 beta on [PyPI](https://pypi.org/project/lionlock/) (currently 1.0.0b2) | Yes |
| Older betas, including 1.0.0b1 | No. Upgrade to the newest beta |
| Unreleased commits on `main` | Best effort |

LionLock is beta software. Interfaces may change before 1.0.0, and no release is approved for
production use. Pin an exact version (for example `lionlock==1.0.0b2`) and read the
[changelog](CHANGELOG.md) before upgrading.

## Scope

These are in scope. Each one is a property LionLock claims, so a counter-example is a vulnerability.

- **Gate fails open.** A bundle or policy that passes validation but produces a weaker action than
  the rule in [docs/GATING_POLICY.md](docs/GATING_POLICY.md) and spec LL-0002 requires. This
  includes raising a score that lowers the action, or an invalid setting that is accepted instead
  of refused.
- **Non-determinism.** The same input and policy giving a different decision or score across runs,
  machines, environment settings or supported Python versions (3.10 to 3.14).
- **Network or AI in the runtime.** Scoring or gating opening a network connection, or loading a
  machine-learning framework.
- **Audit-log integrity.** An edit, reordering or removal inside a TrustVault log that
  `TrustVaultLogger.verify_chain()` does not report, or a way around a stored chain head, within the
  limits described in [docs/AUDIT_LOGGING.md](docs/AUDIT_LOGGING.md).
- **Privacy.** Raw prompt or response text, client IP addresses, tokens or keys reaching a telemetry
  snapshot, an upload or the receiver's files or logs.
- **Telemetry receiver.** Bypassing token checks or install binding, getting a malformed or
  tampered snapshot accepted, writing outside the data directory, or exhausting the server beyond
  its documented size, deadline and connection limits.
- **Credentials.** An API key or upload token sent over plain HTTP to a host other than localhost,
  forwarded through a redirect, or written to a log.
- **Release integrity.** A file on PyPI that does not match the tagged source, or a way to change
  what the publish workflow uploads.

These are known, documented limits. They are not vulnerabilities, but we welcome improvements as
ordinary issues or pull requests.

- The hash chain uses unkeyed hashes. On its own it cannot show that a whole log was rewritten by
  someone who can write the file. Keeping the chain head somewhere that writer cannot change
  closes this; see [docs/AUDIT_LOGGING.md](docs/AUDIT_LOGGING.md).
- Privacy scrubbing is heuristic. It can miss short, unlabeled text, and it can reject long
  descriptive values.
- The fatigue score is not calibrated, and scoring is designed for English text.
- Anyone who can edit LionLock's configuration can turn gating off. This is a setting, not a bypass:
  any decision whose action it changes records `policy_adjustment = "gating_disabled"`.
- The reference receiver must run behind a TLS-terminating reverse proxy, as documented. Running it
  exposed directly is a deployment error.
- A vulnerability in a dependency belongs to that project. Tell us too if the way LionLock uses the
  dependency makes it reachable.
- A scanner report on its own, without a demonstrated effect on LionLock, is not a vulnerability.

When testing, use only your own installation and synthetic data. Do not test against systems or
data you do not own.

## How releases are protected

- Releases are uploaded only by the [publish workflow](.github/workflows/publish.yml), from a
  GitHub release tag, through PyPI Trusted Publishing. No long-lived PyPI token exists.
- The workflow refuses a tag that does not match the version in `pyproject.toml`. It builds with
  `scripts/reproducible_build.py`, then installs and tests the exact wheel and sdist in a fresh
  environment before the upload step can run.
- Only the upload step can request a PyPI identity token, and it runs in the protected `pypi`
  deployment environment.
- Builds are reproducible. Anyone can rebuild a release from its tag with
  `python scripts/reproducible_build.py dist`, using `build==1.6.1`, and compare the sha256 of each
  file with the files on PyPI. [docs/RELEASING.md](docs/RELEASING.md) gives the full procedure.

## Running LionLock securely

### Logs and records

- Write logs to a directory with restrictive permissions, never a world-writable path. LionLock
  creates its own log and telemetry files owner-only.
- Rotate or archive TrustVault logs regularly so audits stay manageable.
- Check a log with `TrustVaultLogger.verify_chain()` before relying on it. The hash chain shows that
  records were not edited, reordered or removed in the middle. To also catch a full rewrite, keep
  the latest chain head (its hash and record count) somewhere the log's writer cannot change, and
  compare against it. See [docs/AUDIT_LOGGING.md](docs/AUDIT_LOGGING.md).
- `tools/lockdown.sh` writes a SHA-256 manifest of the tree, plus an OpenTimestamps proof when the
  `ots` client is installed. A manifest shows whether files changed after it was made. It does not
  show who wrote them.

### Model connector

- An API key is read only from the environment variable you name in `api_key_env`.
- LionLock refuses to send a key over plain `http://` to any host other than localhost, and never
  follows redirects, so a key cannot be forwarded to another host.

### Telemetry

- Logging is local by default (`logs/lionlock.db`). Uploads are off unless you turn them on, and
  they are always refused while `DO_NOT_TRACK` is set.
- An upload endpoint must use `https://`; plain `http://` is accepted only for localhost.
  Redirects are never followed.
- Uploads contain only the allowlisted fields in [docs/TELEMETRY.md](docs/TELEMETRY.md). They are
  sent and stored as files rebuilt from validated rows. The receiver re-applies the same policy and
  treats every snapshot as untrusted input.
- The receiver binds to localhost by default. Put a TLS-terminating reverse proxy in front of it,
  issue one token per deployment with `scripts/log_token_tool.py` (see
  [docs/TELEMETRY.md](docs/TELEMETRY.md)), and keep client addresses out of the proxy's access logs. The receiver itself never logs or stores client addresses.

### Privacy trade-offs

- Key-based scrubbing blocks known prompt and response field names.
- Value-based scanning rejects obvious markers (for example `prompt:` or `response=`) and large
  free-text strings.
- These checks are heuristic, as noted under Scope. Do not pass raw prompt or response text to
  LionLock's logs: hash, summarize or redact it before logging.
- The canonical SQL writers for Module 05 events and missed-signal events apply value scanning.
  Other logs may apply only key-based scrubbing.

### Failsafe encryption keys

Failsafe encryption (the optional `failsafe` extra) uses Fernet from the `cryptography` library:
AES-128 in CBC mode, with each token authenticated by HMAC-SHA256.

Storing the key:

- Keep the Fernet key in a secrets manager (for example AWS Secrets Manager, HashiCorp Vault,
  Azure Key Vault or Kubernetes Secrets). Never commit it to version control.
- Expose it to LionLock as an environment variable, and set `failsafe.key_env` in `lionlock.toml`
  to that variable's name. The default name is `LIONLOCK_FAILSAFE_KEY_B64`.
- The key must be base64-encoded, as produced by `cryptography.fernet.Fernet.generate_key()`.

Rotating the key:

1. Generate a new key and store it in your secrets manager:
   ```python
   from cryptography.fernet import Fernet

   new_key = Fernet.generate_key()  # store this base64 string in your secrets manager
   print(new_key.decode("utf-8"))
   ```
2. Update the secret in your infrastructure. Never commit it.
3. Redeploy the applications that read it.
4. Optionally archive older encrypted events. LionLock only encrypts. To read an old event, decrypt
   it with the old key using `cryptography.fernet.Fernet(old_key).decrypt(token)`.
5. Test failsafe behaviour with the new key, then destroy the old key.

If you suspect a key has leaked:

1. Revoke the old key in your secrets manager immediately.
2. Generate and deploy a new key.
3. Review every event encrypted under the old key, and regenerate any that need it.
4. Tell your security team, and check access logs for unauthorized use of the key.

Each Fernet token records when it was created. LionLock never reads tokens back, so it never checks
their age. Check it yourself when you decrypt, if it matters to you.

## Checks we run

- `make verify` runs on every pull request: tests, determinism fingerprints, lint and type
  ratchets, and a privacy check that rejects added home paths, emails, private IP addresses and
  credentials.
- Secret scan: `bash tools/secret_scan.sh`.
- Dependency audit: `bash tools/security_audit.sh`, which needs `pip-audit` from
  `pip install -e '.[dev]'`.
- Dependabot opens weekly pull requests for dependency updates.
- We fix vulnerabilities when we find them. If a specific issue must be allowed for a while, we
  record it in an allowlist with the reason and the date before suppressing it.
- No secrets belong in this repository. Any leaked secret is rotated immediately.
