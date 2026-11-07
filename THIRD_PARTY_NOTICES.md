# Third-party source and license notices

This file tracks provenance for third-party code and specifications incorporated into dinit-logind.

## Current status

No upstream implementation source has been copied into the repository scaffold.

## Planned references (not runtime dependencies)

- systemd v262.2: primary behavioral/API reference for login1 and logind. Review each source file's license and copyright notice individually; systemd files commonly carry LGPL-2.1-or-later notices.
- Turnstile: reference for session, PAM, runtime-directory, linger, and Dinit user-service lifecycle functionality. Verify the exact license and preserve required notices for every adapted file.
- Dinit: native service-manager backend target. Follow the upstream license and API contract.

## Required process before importing code

1. Record upstream repository, immutable commit/tag, source path, copyright holders, SPDX identifier, and local destination.
2. Read the complete license and file-level notices.
3. Preserve copyright and attribution notices; never remove comments to obscure provenance.
4. Add required license texts and notices.
5. Record modifications and keep adapted code separable where practical.
6. Review combined-distribution license compatibility before committing.

Update this ledger in the same change that introduces third-party-derived code.
