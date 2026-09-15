# Changelog

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
