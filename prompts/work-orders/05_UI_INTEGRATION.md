# Work Order 05 — one-hotkey UI and runtime integration

## Ownership

`apps/desktop/**`; cross-crate composition changes require integrator approval.

## Objective

Wire the Slint window, target chooser, tray, engine, recent history, settings, and status feedback into the fastest possible workflow.

## Required workflow

- default target configured once;
- one hotkey sends current clipboard;
- chooser appears focused and keyboard-operable;
- receiver notification identifies source;
- main window may remain closed;
- exact statuses: sent, offline, refused, clipboard failed, uncertain;
- recent list permits manual copy/retry with a new explicit action;
- no delayed direct push;
- accessibility labels and full keyboard reachability.

## Acceptance

A user can copy on BMST, press one hotkey, switch to BZOT, and paste with no mouse and no intermediate window. LocalSend-style destination/file-picker steps are absent.
