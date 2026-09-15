# Using TailVault

## Connect and settings

Connect Tailscale using your user account, then enter your Setec server's HTTPS
origin when you first open TailVault. The app has no default server address and
does not discover one automatically.

Your address is saved in `~/Library/Application Support/TailVault/settings.json`.
Change it in **Settings** (⌘,), which is available even while Tailscale is offline.
Saving a new address clears the old view and reconnects.

**Open vault** shows progress while TailVault checks your local Tailscale
connection, then loads secret metadata from your saved server. If a step fails
or times out, the app shows an error and lets you try again. You do not need to
run a curl command before opening the vault.

Your Tailscale ACLs define which secrets you can list, read, and change. Setec
enforces those permissions. Seeing a secret in the list does not necessarily
mean you have permission to reveal or edit it.

## Manage secrets

- Search names or expand paths in the sidebar, then select a secret.
- Use **+** to create a secret from text, a generated password, or a file.
- Use **Edit** to save a new version. **Activate** makes a version current.
  Setec may reuse the latest version if you save the same bytes again.
- Reveal versions independently to compare them, or copy or download a value.
  Revealed values hide after 30 seconds or when the app loses focus.
- **Copy curl** copies a command for fetching the active version. **Use in
  terminal** lets you choose a version and output format. Run the command from
  a device with Tailscale access and permission to read that secret.

## Shortcuts

| Shortcut | Action |
| --- | --- |
| ⌘K | Search |
| ⌘N | New secret |
| ⌘R | Refresh |
| ⌘, | Settings |
| ⇧⌘L | Hide the vault |

Hiding cancels pending work and clears displayed data. **Open vault** resumes
using your current Tailscale identity. Hiding is a privacy control, not a
separate authentication or encryption boundary. Completed downloads and
clipboard copies remain outside the app; TailVault cannot recall them.
