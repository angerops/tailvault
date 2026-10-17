# Changelog

## v0.1.2

- Rename Edit to New version to reflect how Setec stores secret values.
- Clarify that Show entered value applies to the new value and disable it
  while the input is empty.
- Search names and paths across all listed secrets, regardless of the selected
  sidebar path. Clearing search returns to the selected path.
- Reuse the local Tailscale client to prevent idle connections from accumulating
  while continuing to read the current identity on every check.

## v0.1.1

- Show immediate progress while opening the vault and checking Tailscale.
- Show an error and allow retry when settings, connection checks, or secret
  metadata take too long to load, or when opening is interrupted.
- Prevent canceled or late opening requests from disturbing a newer view.
- Explain local Tailscale connection failures without exposing daemon details.
- Support Tailscale status responses that provide a stable device ID without
  a numeric node ID.

## v0.1.0

- Initial release for macOS Sequoia 15 or newer on Apple Silicon.
