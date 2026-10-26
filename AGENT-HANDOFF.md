# Build VaultRewind end to end

Read VAULTREWIND-SPEC.md in full before implementing anything. It is the product and engineering contract. Build the complete application, not a mock dashboard, a proof of concept or a collection of backup shell scripts.

## Product

VaultRewind is a self-hosted manager for complete backups and restores of multiple Vaultwarden instances over SSH. The golden rule is **One-click backup. One-click restore.** After onboarding, users must never need to copy files, run database commands or reconstruct containers manually to complete those actions.

The owner confirmed version one supports Vaultwarden on Linux Docker with SQLite, including bind directories and supported local named volumes. Support local persistent storage on the controller, S3-compatible object storage and Google Drive. Restore defaults to the original instance after one concise target-specific confirmation; a prepared alternate server is also a supported destination. Official Bitwarden, native Vaultwarden installations and external database engines are future work.

## Before implementation

1. Inspect repository instructions and existing files. Preserve unrelated work. Do not add a Codex or Anthropic co-author trailer to any commit.
2. Produce a short implementation plan covering all release-one requirements and AC01 through AC36 in the specification. Map each acceptance ID to a test or evidence procedure.
3. Select current supported dependency versions using official documentation and Context7 where available. Pin versions in lockfiles and images. The proposed architecture is Python/FastAPI, React/TypeScript, PostgreSQL, a database-backed worker queue, AsyncSSH, a constrained remote helper, restic and rclone.
4. Build only against synthetic data and disposable Linux/Docker/systemd fixtures. The owner's existing Vaultwarden server is read-only and is not an authorized test or deployment target. Do not connect to it, install helpers, run backups, stop services or restore anything there.

## Correctness requirements

Capture every persistent instance file, not only the database. Include attachments, Sends, configuration, signing keys, secrets/environment files, ownership metadata, a validated recovery deployment definition and the exact saved Vaultwarden image. Unknown regular files must be inventoried and captured. Permission failures are fatal to completeness; do not chmod production files to hide them.

Use a controlled source stop for a coherent full-instance capture, with a remote watchdog and durable operation journal armed first. Copy source data to local staging, then restore its original service state before normalization, transfer or upload. Normalize only the staged SQLite copy through a supported backup mechanism that incorporates its WAL. Never confuse a consistent database with a consistent whole application.

Every backup is an immutable dated logical snapshot, even if content is unchanged. Store it encrypted in standard restic repositories. Capture once and track each local/cloud copy independently. Commit and read back the manifest before marking a copy complete. Required-copy failures and source recovery failures must be visible independently from valid stored content.

For restore, bind confirmation to an exact snapshot and target. Verify and stage before downtime. Replacing an existing target requires a pinned durable local safety snapshot and preservation of the old generation. Use journaled generation switching, validate the candidate without public exposure, and activate only after validation. Before activation, failures recover the original. After activation may have happened, never silently revert and discard possible new client writes; reconcile or report needs_attention. Implement the exact boundary in the specification.

Retention means all snapshots captured within X rolling UTC days, not X files or one snapshot per day. Protect pins, safety snapshots, active restore inputs and the last complete/tested recovery points. Freeze automatic deletion during backup failure, overdue state or uncertainty. Calculate explicit deletion IDs under locks. Do not blindly use restic keep-within as a substitute for the defined wall-clock rule.

Use physical resource identities and controller plus helper-side locking so two workers or duplicate registrations cannot act on the same data simultaneously. Persist operation IDs, phase evidence and fencing tokens. Reconcile ambiguous operations after crashes instead of repeating destructive commands blindly.

Google Drive authorization, writable refresh-token handling and encrypted persistence of rotated credentials must actually work. Complete the UI setup and recovery flows; an unimplemented provider dropdown is not support. Use dedicated test-account credentials supplied privately when needed, never ask for secrets in chat or commit them.

The controller must be recoverable after total loss. Ship an independently encrypted recovery kit and offline recovery/import CLI that can discover and restore existing repositories without the original controller database or master key. Test that scenario.

## Execution order

Prove a command-line synthetic backup/restore round trip first. Then implement constrained SSH access, remote recovery and crash handling; complete captures and local storage; safe original/alternate restores; retention and scheduling; S3 and Google Drive; UI/authentication/audit; automated restore testing; recovery tooling; packaging and documentation. All of these remain required in the final delivery.

Use real Vaultwarden, SSH, SQLite and restic integration boundaries. Test S3 with MinIO and the watchdog/reboot guarantees in a disposable systemd-capable Linux VM. Keep fault-injection hooks test-only. Add browser tests for the actual workflows, not only mocked success states. Use source documentation as a guide and the specification's acceptance matrix as the completion standard.

## Final delivery

Deliver working source, migrations, locked dependencies, helper/protocol, production and development Compose files, UI, API/OpenAPI, CLI and offline recovery, synthetic test harness, provider integrations and operator documentation. Record evidence against every acceptance ID, including fault injection and controller-loss recovery.

Run appropriate checks and report exact passing results, remaining limitations and any externally blocked live-provider tests. Never claim Google Drive is release-verified without its real authorization/refresh/backup/restore evidence. Do not claim one-click restore based on merely extracting an archive or starting a container.

Do not publish, create cloud accounts, upload real vault data, modify the owner's server or deploy to production without separate authorization. Finishing the local implementation and synthetic verification is authorized by this handoff; changing the owner's production environment is not.

