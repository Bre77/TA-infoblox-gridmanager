# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- This app runs on `splunk_input_runtime` (https://github.com/Bre77/splunk-input-runtime), not `splunklib`/`splunk-sdk`. `lib/requirements.txt` pins it to an exact commit archive URL with a `sha256:` hash recorded in a comment above it (no PyPI package exists yet, so there is no `==version` line to pin against). Bump both the commit and the recorded hash together when the runtime releases a new version; never point at a branch.
- Credential handling goes through `self.context.credentials.protect_input_fields(...)` (see `bin/infoblox_gridmanager.py`), not manual `storage_passwords` list/delete/create calls. This preserves the credential identity `(owner=nobody, app=TA-infoblox-gridmanager, realm=<stanza name>, username=password)` that existing installs already have - do not change that tuple without a captain-level decision; it strands users' stored secrets. `username` (the Infoblox login name) is a plain stanza setting, not a stored secret - only `password` goes through `storage/passwords`.
- `.build.sh` vendors `lib/` fresh on every build (`pip install -t lib -r lib/requirements.txt --no-dependencies`); `lib/` is gitignored except `lib/requirements.txt`. Do not commit vendored packages into `lib/`.
- The runner (`Script.run_script`) owns `EventWriter.close()`; app code must not call it explicitly.
- This app has no checkpoint file today - collection is a full re-poll of `/wapi/<version>/network` every interval, not incremental. Do not add one without a deliberate design decision.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
