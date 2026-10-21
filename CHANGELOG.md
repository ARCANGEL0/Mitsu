# Mitsu history

These versions mark development milestones in the Git history. Versions before
1.4.21 were assigned retrospectively; skipped numbers do not represent releases.
Each milestone has a matching Git tag and consistent runtime and package versions.

## 1.4.21

- New messages interrupt the active run in every mode. Redirects pause investigation
  tools until the next direction is chosen in a dialog.
- Guided mode pauses between investigation steps so the next dialog can use the
  results just collected. Intel updates remain available while paused.
- Completed tool results survive cancellation and errors. Interrupted tool calls
  get matching results so the conversation stays usable with both provider protocols.
- Final replies end the turn without another completion check or automatic continuation.
- Recent operator directions and validated access stay available when choosing the next step.
- Click a code block or `<copytag>value</copytag>` to copy it. The message menu also
  offers Stop while a response is running.

## Earlier milestones

| Version | Changes |
| --- | --- |
| 1.4.2 | Message copying and conversation/workspace rewind; dialog and activity display fixes. |
| 1.4.1 | Bounded artifact search and Intel notes; provider work off the UI loop and repeated-command limits. |
| 1.4.0 | `/workdir` selects a persistent workspace for each session. |
| 1.3.2 | Session uptime, command output cards, and Intel MCP improvements. |
| 1.3.1 | Vulnsearch presentation and evidence capture; session timestamps and automatic naming. |
| 1.3.0 | Expanded Intel categories, session context, and the tabbed Intel panel. |
| 1.2.1 | Interactive dialogs, command handoff, and chat input/scroll improvements. |
| 1.2.0 | Image attachments and provider image input, following chat exports and vulnerability search. |
| 1.1.0 | Initial Mitsu terminal companion, providers, tools, and session UI. |
