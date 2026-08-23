# Work Order 05 — active-window UI and runtime integration

## Ownership

`apps/desktop/**`; cross-crate composition changes require integrator approval.

## Objective

Wire the Slint window, target chooser, tray, engine, recent history, settings, and status feedback into the fastest possible workflow.

## Required workflow

- default target configured once;
- active-window controls send explicitly selected clipboard text;
- chooser appears focused and keyboard-operable;
- receiver notification identifies source;
- main window may remain closed;
- exact statuses: sent, offline, refused, clipboard failed, uncertain;
- recent list permits manual copy/retry with a new explicit action;
- no delayed direct push;
- accessibility labels and full keyboard reachability.

## Acceptance

A user can open meshelf on BMST, click Paste clipboard, click Send, switch to BZOT, and paste. No global shortcut or intermediate destination/file-picker step is required.
