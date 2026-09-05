# Ubuntu recovery component evidence

This records **component-level checkpoint evidence**, not final installation or
cold-recovery acceptance. Disposable file fixtures cannot establish physical
storage topology, firmware behavior, or successful boot. The final VM report
must supply those observations on its frozen source tree.

## Observed checkpoint gates

- The complete gate was rerun after the platform-safety and canonical refusal
  probe checkpoints: task `266512emsb` passed in 348.2 seconds on 2026-09-05.
  It included `make -C installer check` (including formatting and cross-platform
  checks), 31 install regressions, focused refusal-probe checks, shell syntax and
  diff checks. This supersedes the earlier formatting-only failure. Real refusal
  results and the remaining cold-cut cases must still be recorded separately.

- After artifact mount isolation fix `cb7d6c4`, the complete installer gate,
  all 27 install shell/harness regressions, shell syntax checks and diff checks
  passed independently (task `208545pea1`, 223.9 seconds). The new ordering
  regression checks that the Ubuntu bootstrap bind is isolated and removed
  before artifact promotion. A fresh real VM rerun is required to establish
  stable image hashes and successful deployment after this change.

- Later complete-project gate `make -C installer check` passed on 2026-09-05
  (task `885036uqkq`, 220.5 seconds), after the public shell routing fixes.
- Static packaging through `make -C installer/controller ubuntu-static` passed.
  The resulting executable was checked as static ELF with no interpreter and its
  read-only missing-plan refusal was exercised. This is packaging evidence, not
  deployment acceptance.
- After VM harness review through `b483ead`, independent standard discovery
  `python3 -m unittest discover -s install/tests -v` passed all 26 tests, and
  `git diff --check` passed (task `5398065r6n`). The harness regressions include
  path containment, process identity, fixed offline VM arguments and rejection
  of inconsistent cold-witness evidence. They do not replace real VM cuts.
- Actual earlier-controller cold recovery, boot and completed no-write behavior,
  plus the final-code firmware refusal, are recorded separately in
  [UBUNTU_RECOVERY_ACCEPTANCE.md](UBUNTU_RECOVERY_ACCEPTANCE.md). Its open final-code
  rows remain open despite these component gates.

- `make -C installer/controller check`: passed at the `3cd2ee6` checkpoint on
  2026-09-05, background task `5293078yxp`, 41.7 seconds. This includes formatting,
  all controller tests, strict Clippy, and the Windows MSVC cross-check.
- `make -C installer check`: passed on 2026-09-05, task `584154nkx3`, 301.4 seconds.
  This checks the complete project, including the existing core, staging,
  controller, model and VM-runner contracts. Later scope changes and the final
  acceptance tree must be checked again. Its Windows/physical ledger still has
  explicitly open hardware and real-campaign requirements.
- Independent replay regressions are in
  `installer/controller/tests/ubuntu_replay_adversarial.rs` (`1da6d02`). All 16
  passed at the checkpoint. Existing Ubuntu recovery tests also passed.
- Graph evidence tests are in
  `installer/controller/src/ubuntu/graph_driver.rs`. All four passed. Their
  loops exercise every pinned transition's required predicates, rather than
  treating a test count as predicate coverage.

## Requirement-to-observation map

| Requirement | Concrete observed component behavior | Still needs end-user acceptance |
|---|---|---|
| UR-01 | No real public-path acceptance recorded in this component report. | Public orchestration and artifact-only target boundary in Ubuntu VM. |
| UR-02 | `pinned_identity_digest_and_model_separation_hold` rejected altered bytes and the wrong model. `every_guard_authorization_and_precondition_is_enforced` rejected each missing and false prerequisite. `every_postcondition_and_action_is_required_before_state_advance` rejected each missing postcondition and unfinished action list. `mutation_requires_intent_and_exact_action_order_without_aliases` rejected aliases, reordering, repeated effects and missing durable-intent evidence. | Verify actual adapter observations and effects agree with the graph during real deployment. |
| UR-03 | No networkless deployment acceptance recorded here. | Build all sources first, then disconnect network for deployment and cold resume. |
| UR-04 | `plan_drift_and_committed_journal_corruption_stop` rejected changed plan geometry and corrupted committed journal bytes. | Real artifact, target and recovery-identity substitution cases, with no new writes. |
| UR-05 | No bootable-host proof recorded here. | Mounted/root/ESP/swap/state overlap refusals and preserved host cold boot. |
| UR-06 | No real enumeration-change proof recorded here. | Same-device renumbering succeeds, changed/duplicate identity refuses. |
| UR-07 | No concurrent-writer acceptance recorded here. | Competing public deploy/resume and mount attempts cannot interleave effects. |
| UR-08 | `status_rejects_hardlinked_journal` and `status_rejects_symlinked_journal` refused unsafe aliases. `status_does_not_truncate_torn_journal_tail` returned an error and preserved the journal byte-for-byte. `valid_authorized_history_is_read_only` preserved both journal and target bytes. | Interrupted durable publication, real restart recovery, and production protected-path boundaries. |
| UR-09 | `dangling_intent_is_reconciled_only_for_bound_range` completed a pending chunk. `commit_before_advance_resume_appends_only_advance` recovered the commit/advance gap. Independent malformed-history cases rejected missing intent/commit, premature advance and wrong chunk digest. | External power loss at intent, effect, readback, commit and advance boundaries. |
| UR-10 | `corrupt_committed_chunk_is_never_overwritten` refused a committed mismatch and retained target bytes. `staged_but_unauthorized_transaction_never_writes_target` returned refusal and preserved the exact disposable target. `chunk_intent_cannot_skip_durable_deployment_start` rejected the skipped phase. | Cold, networkless resume from preserved executable and plan, without shell rerun. |
| UR-11 | `deploy_verifies_and_completed_resume_never_repairs` preserved a later target edit after completion. `restart_after_verified_completes_without_duplicate_verification_record` reached complete with exactly one Verified record. Premature verification/completion and records after terminal states were rejected. | Full target UEFI boot and completed public resume with no target writes. |
| UR-12 | No real firmware/ESP preservation observation recorded here. | Compare preserved boot assets and firmware state across build, deployment and power loss. |
| UR-13 | No cold-recovery UX acceptance recorded here. | Boot the preserved host, remove source checkout/network, run the documented retained executable. |
| UR-14 | Project gates passed at an implementation checkpoint. | Final frozen-tree gates plus the complete real Ubuntu fault/boot evidence matrix. |

Successful component checks are necessary but do not close the rows whose real
acceptance observations remain outstanding. In particular, legacy-shell boot
results must not be reused as proof of this transactional recovery path.
