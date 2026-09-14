# Security policy

meshelf is not ready for sensitive clipboard data until the release security gate passes.

Do not use a development build to transmit passwords, recovery codes, API keys, private keys, health data, financial information, or confidential work material.

Report security findings privately to the repository owner. Include the exact commit, platform,
Tailscale version, reproduction steps, and whether clipboard contents were exposed or overwritten.

The current candidate is designed around explicit clipboard actions, no clipboard polling, signed
peer identity, bounded transfers, receiver-initiated payload pulls, and private Tailscale binding.
These controls do not replace the unfinished native failure/recovery proof or the final security
and release review.

Interim admission: during functional testing, a meshelf installation that presents a valid signed
identity from the same Tailscale network is recorded and admitted automatically on refresh, without a
pairing code. That applies to desktops and to the Android app. Tailnet membership alone is not enough,
but any meshelf installation on your tailnet can join your shelf, so use it only on a tailnet whose
devices you control. A confirmed pairing ceremony is implemented but deferred.
