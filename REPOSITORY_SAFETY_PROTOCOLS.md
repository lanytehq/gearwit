# Repository Safety Protocols

This repository is public-bound. These rules are a hard gate for humans and
assistants.

## Never commit

- credentials, tokens, passphrases, private keys, or secret-bearing
  environment dumps
- private hostnames, IP addresses, account identifiers, or internal service
  URLs
- local filesystem paths or user names from real machines
- private coordination channels, task identifiers, or operating notes
- customer, client, or engagement-identifying material
- raw prompts, terminal transcripts, tool bodies, or model chain-of-thought
- native session identifiers, controller endpoints, attachment proofs, or
  lease material

Fixtures must be sterile and intentionally authored for public use.

## Agent and controller safety

- Treat process metadata, terminal content, titles, provider events, and
  self-declarations as untrusted input.
- Do not infer model state, intent, or controller authority from process
  presence.
- Keep public seat projections separate from private controller bindings.
- Store private runtime state with user-only permissions outside project git.
- Do not persist raw terminal streams or prompts by default.
- Fail closed when attachment proof, generation, capability, or lease checks
  are missing.
- Do not replay an authority-bearing dispatch after an ambiguous send.

## Repository structure

- Do not use git submodules.
- Schemas precede implementations for public file and wire types.
- Generated bindings never become the source of truth.
- Do not add a required hosted service to the local-first path.
- Do not add a heavyweight monorepo manager without an accepted decision.

## Public git surfaces

Commit messages, branches, PRs, issues, repository docs, schemas, and fixtures
must make sense to a public reader with only this repository. Keep private
planning, coordination, and session history out of them.
