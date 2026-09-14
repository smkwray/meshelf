# Configuration examples

`meshelf.example.json` shows the current per-user state shape: the local device ID, the stored peer
registry, and the receiver's file/folder save destination. The application creates and atomically
updates its real state under the platform's per-user `meshelf` directory; this repository file is not
a launch configuration to fill in by hand.

Never commit real device IDs, installation keys, Tailscale addresses, destination paths, or clipboard
content. There is no default target, start-at-login setting, notification setting, history limit, or
`allow_clipboard_push` field.

The Tailscale grant example is optional defense in depth. It does not replace signed protocol-2
identity checks or application-level peer authorization.
