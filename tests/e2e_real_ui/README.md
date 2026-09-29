# Real browser acceptance

This suite runs the source application as a separate process, logs in through
its normal login form, and exercises business functions through visible controls.
Each scenario runs at 1440×900 and 390×844; shell checks also cover 320 and 768 px.

## Run

With the project's development dependencies and Playwright Chromium available:

```powershell
$env:PYTHONUTF8='1'
$env:ANTEUMBRA_E2E_ARTIFACTS = Join-Path $env:TEMP 'anteumbra-ui-evidence'
$env:ANTEUMBRA_UI_ARTIFACTS = $env:ANTEUMBRA_E2E_ARTIFACTS
python -m pytest tests/e2e_real_ui -q --junitxml="$env:ANTEUMBRA_E2E_ARTIFACTS/results.xml"
```

The same suite is the CI browser acceptance lane. Backend CI excludes both browser
directories. `tests/e2e_ui` retains older, service-seeded component regressions;
its navigation was migrated, but its seeded cases are not evidence of a complete
operator workflow. Do not use those shortcuts when extending this suite.

## Isolation and permitted inputs

- A new temporary deployment, credentials and two monitored website roots are
  created for each test. The installed deployment and its configuration are not used.
- Ports are allocated dynamically on loopback; the suite does not use 8080 or 8765.
- Test files contain a harmless YARA marker in a PHP comment. Filesystem writes,
  removals and test-rule uploads simulate external inputs; samples are not executed.
- Login, configuration, scans, record actions, downloads, blocking and inspection
  happen through browser interactions. No `APIRequestContext`, direct HTTP clients,
  request interception, registry seeding, cookie injection or JavaScript state
  mutation is allowed. An architecture guard enforces these shortcuts in scenario files.
- Runtime bootstrap may write the initial configuration and start local counterpart
  servers. After startup, scenario changes to those counterparts use their own
  public HTML control pages; receipts are inspected through those pages.
- Teardown closes browser contexts, stops the owned runtime and local servers, and
  deletes only the fixture's own temporary deployment directory.

## What the external lab proves

`receivers.py` implements a loopback WAF event feed, two HTTP blocking devices,
a webhook receiver and a UDP Syslog collector. Anteumbra sends real requests.
The lab exposes scenarios, failures and received messages in an HTML page so tests
can verify the complete request path without calling either side's business API.

`memory_target.py` implements the deployed probe protocol and checks actual probe
files/tokens. It tests deployment, transport, parsing, evidence storage/download,
and component-removal result handling. It is not a real JVM/Tomcat exploit or an
endorsement of compatibility with a particular commercial WAF/firewall. Those
platforms need separate acceptance against their own implementations.

## Scenario map

| Operator capability | Primary scenario files |
| --- | --- |
| Navigation, bookmarks, back, site scope, language, themes, phone layout (G01/G03/U01) | `test_shell_navigation.py` |
| Login, password change, logout (G02) | `test_operator_admin.py`, `test_password_entrypoints.py` |
| Detection, evidence, source, FP/undo, re-alert, record deletion (R01–R04) | `test_detection_flow.py`, `test_record_actions.py`, `test_review_edges.py` |
| Duty queue aggregation, site scope, grouped review, nested source escape, and response receipts (D03) | `test_duty_workflow.py` |
| Quarantine, restore, permanent deletion and history (Q01) | `test_detection_flow.py`, `test_record_actions.py`, `test_review_edges.py` |
| WAF profiles, reports, selected IPs, file clusters (P01–P03) | `test_investigation_workflow.py`, `test_integrations.py` |
| New/known scan findings, stop, failure, history, report, partial quarantine (S01–S03) | `test_scanner_workflow.py`, `test_management_flows.py` |
| Live/history logs, filters, exports, access-analysis state (L01–L03) | `test_operator_admin.py`, `test_review_edges.py` |
| Device selection, partial block failures, site ledger, notes, unblock, exports (F01/F02) | `test_integrations.py`, `test_investigation_workflow.py` |
| Probe, component evidence, manifest/download, remediation and failure (M01–M04) | `test_memory_workflows.py` |
| Rules upload/read/edit/validate/selection/delete (Y01) | `test_management_flows.py`, `test_review_edges.py` |
| Site inventory, configuration three views, structure/batch edits, conflicts, versions/restore (C01–C03/C08–C11) | `test_management_flows.py`, `test_operator_admin.py`, `test_configuration_depth.py` |
| Notifications, secrets, plugins and account configuration (C04–C07) | `test_operator_admin.py`, `test_configuration_depth.py`, `test_password_entrypoints.py` |
| Storage/health views, SIEM formats and live stream, registry/WAL/sessions/reload (D01/D02/O01–O06) | `test_management_flows.py`, `test_integrations.py`, `test_configuration_depth.py` |
| Cross-page selection, exclusions, filter redraws, site isolation, partial failure and retry, bulk restore | `test_bulk_selection.py` |
| Site-relative access attribution, duplicate basenames, query strings, cumulative counts | `test_communication_flow.py` |
| Rule upload/edit/delete changes actual detection; explicit manual scan extensions | `test_rule_effectiveness.py` |
| Cross-page profile IP selection, multi-IP/device receipts, maintenance cancellation | `test_operator_edges.py` |

The map identifies checks; it is not a claim that every conceivable condition is
exhaustively covered. A successful current run is established by its JUnit result,
not by this table. Proposed features such as rule-to-detection reverse navigation
(Y02), shift assignment and tenant RBAC are not existing capabilities being migrated.

Maintenance checks exercise the actual UI commands and their returned results.
They do not claim crash-recovery or corrupted-WAL coverage. Clipboard checks grant
the isolated browser context clipboard permissions, copy through the profile
control, and paste into a visible input. They do not test denied permissions or
OS clipboard interoperability. Notifications are delivered to the loopback webhook;
external SMTP and WeChat delivery are not exercised.

Communication checks use owned access-log inputs and visible record/detail counts.
They do not establish compatibility with every rewrite or document-root alias.
Rule effectiveness checks scan fresh files to completion after each UI edit/delete;
absence of a finding is asserted on the completed scan, not inferred from a delay.
Maintenance cancellation is covered for registry compaction; stale-response guards
are reviewed in source, not proven by a controlled browser race. Session checks do
not seed expired sessions or prove crash recovery. Blocking supports multiple IPs
in its action form; the ledger itself has no cross-page row selection control.

## Manual development preview

Run `python tests/e2e_real_ui/preview.py --artifacts <fresh-local-directory>`.
The printed `preview.json` provides the console, device-lab URLs, disposable login,
and the two temporary website roots. Add a harmless PHP comment containing
`ANTEUMBRA_E2E_MARKER` to either root to exercise detection, then use the console to
investigate and respond. Use the device lab's visible buttons to generate WAF events
or simulate a device failure. No product API calls are necessary.

The preview expires after four hours by default. Ctrl+C, or creating the printed
`stop_file`, stops its runtime and cleans up its own temporary deployment. The
artifact folder retains logs and disposable credentials; keep it outside Git.

## Failure evidence

The artifact directory defaults to the OS temporary directory. Failures keep a
screenshot, visible page text, Playwright trace, runtime log and diagnostics. Expected
HTTP refusals must be declared with the exact path and status using
`expected_http_error`, and the scenario must assert the user-visible failure.
Other HTTP failures, JavaScript errors and unattributed browser errors fail the run.

Artifacts contain disposable test data and are not committed. Traces may contain
those test credentials; do not run this fixture against a personal deployment.
