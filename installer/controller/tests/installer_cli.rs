//! PH-17 tests: the pre-hardware installer CLI.
//!
//! These cases run the real binary against deterministic fixtures, so they test
//! what an operator actually sees rather than an internal API. The critical
//! properties are that the confirmation shows every value the safety contract
//! requires, that a mismatched plan or display is refused, that recovery states
//! are explained in operator terms, and that the binary exposes no way to name a
//! real disk.

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    // The integration test binary lives next to the built CLI.
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("jstack-installer")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../core/generated")
        .join(name)
}

struct Output {
    status: bool,
    stdout: String,
    stderr: String,
}

fn cli(arguments: &[&str]) -> Output {
    let output = Command::new(binary())
        .args(arguments)
        .output()
        .expect("the installer CLI must be built before this test runs");
    Output {
        status: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn plan() -> String {
    fixture("example-plan.json").to_string_lossy().into_owned()
}

fn display() -> String {
    fixture("example-plan-display.json")
        .to_string_lossy()
        .into_owned()
}

fn confirmation() -> String {
    fixture("example-confirmation.json")
        .to_string_lossy()
        .into_owned()
}

/// The confirmation must show every value the safety contract names: the disk,
/// each partition GUID, before and after sizes, and the exact interval.
#[test]
fn the_confirmation_shows_every_contractually_required_value() {
    let output = cli(&["confirm", &plan(), &display()]);
    assert!(output.status, "confirm failed: {}", output.stderr);
    let text = &output.stdout;

    // Disk and plan identity.
    assert!(
        text.contains("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        "disk GUID"
    );
    assert!(
        text.contains("c558b122396cde57c2ec9937a9d599ed4176867d8cef8ec3d762d3cf3c3bcd56"),
        "plan hash"
    );

    // Before and after sizes, in exact and human terms.
    assert!(text.contains("400.00 GiB"), "size before");
    assert!(text.contains("360.00 GiB"), "size after");
    assert!(text.contains("40.00 GiB"), "space released");

    // The exact allocation interval, in bytes.
    assert!(text.contains("387101753344"), "interval start in bytes");
    assert!(text.contains("430051426304"), "interval end in bytes");

    // Every created partition GUID and type GUID.
    for value in [
        "6cf33821-877f-8143-b0fa-adb670a57c0f",
        "4ea72850-8bb9-8ad1-a15c-1f2268832b44",
        "bc13c2ff-59e6-4262-a352-b275fd6f7172",
        "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
    ] {
        assert!(text.contains(value), "missing {value}");
    }

    // Untouched partitions are named explicitly, so the user can see what is
    // preserved rather than inferring it.
    for value in [
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "44444444-4444-4444-8444-444444444444",
    ] {
        assert!(text.contains(value), "missing preserved partition {value}");
    }

    // The Windows partition is identified as the one being shrunk.
    assert!(text.contains("33333333-3333-4333-8333-333333333333"));
    assert!(text.contains("SHRUNK"));

    // Rollback objects are disclosed before approval.
    assert!(
        text.contains("InstallerFinalizer"),
        "finalizer rollback object"
    );
    assert!(
        text.contains(r"\EFI\JStack\Installations"),
        "ESP rollback object"
    );

    // The user is told nothing has happened yet.
    assert!(text.contains("Nothing has been changed yet"));
}

/// A display document describing a different plan must be refused, so the user
/// can never approve values that do not belong to the plan being executed.
#[test]
fn a_display_document_for_another_plan_is_refused() {
    let output = cli(&["confirm", &plan(), &confirmation()]);
    assert!(!output.status, "a mismatched display must be refused");
}

/// A plan whose hash does not match its body is refused before rendering.
#[test]
fn a_plan_whose_hash_does_not_match_its_body_is_refused() {
    let temporary = std::env::temp_dir().join("jstack-cli-tampered-plan.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(plan()).unwrap()).unwrap();
    // Change a displayed size without recomputing the hash.
    document["body"]["windows_resize"]["target_size_bytes"] = serde_json::json!(1);
    std::fs::write(&temporary, serde_json::to_vec(&document).unwrap()).unwrap();

    let output = cli(&["confirm", &temporary.to_string_lossy(), &display()]);
    let _ = std::fs::remove_file(&temporary);
    assert!(!output.status, "a tampered plan must be refused");
    assert!(
        output.stderr.contains("plan hash"),
        "the error must name the hash mismatch: {}",
        output.stderr
    );
}

/// A recorded confirmation is validated against both the plan and the display.
#[test]
fn a_recorded_confirmation_is_validated_against_the_plan_and_display() {
    let output = cli(&["confirmed", &plan(), &display(), &confirmation()]);
    assert!(output.status, "confirmed failed: {}", output.stderr);
    assert!(output.stdout.contains("confirmation accepted"));

    // Swapping the display invalidates the confirmation.
    let output = cli(&["confirmed", &plan(), &confirmation(), &confirmation()]);
    assert!(!output.status);
}

/// The virtual run reaches the completed terminal and reports it in operator
/// terms, with a nonempty durable journal.
#[test]
fn the_virtual_run_reaches_the_completed_terminal() {
    let output = cli(&["run", &plan()]);
    assert!(output.status, "run failed: {}", output.stderr);
    let text = &output.stdout;
    assert!(text.contains("terminal state: terminal.completed"));
    assert!(
        text.contains("virtual machine"),
        "the run must say it is virtual"
    );
    assert!(
        text.contains("The install completed and both systems were verified to boot"),
        "the terminal must be explained in operator terms"
    );

    // Every transition reports its resulting control state, so the operator can
    // see progress rather than a single opaque success.
    for transition in [
        "begin_preflight",
        "reserve_windows_space",
        "create_xbootldr",
        "deploy_jstack_image",
        "complete_after_first_boot",
    ] {
        assert!(text.contains(transition), "missing {transition}");
    }

    let records = text
        .lines()
        .find_map(|line| line.strip_prefix("journal records: "))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .expect("the run must report a journal length");
    assert!(
        records > 50,
        "expected a full durable journal, saw {records}"
    );
}

/// The BitLocker path also completes, exercising the suspend and restore
/// transitions the no-BitLocker path skips.
#[test]
fn the_bitlocker_virtual_run_also_completes() {
    let output = cli(&["run", &plan(), "--bitlocker"]);
    assert!(output.status, "bitlocker run failed: {}", output.stderr);
    assert!(output.stdout.contains("terminal state: terminal.completed"));
    assert!(output.stdout.contains("prepare_bitlocker"));
    assert!(output.stdout.contains("suspend_bitlocker_after_finalizer"));
    assert!(output.stdout.contains("restore_windows_security"));
}

/// Every terminal and recovery state has actionable guidance, and the dangerous
/// ones say explicitly what not to do.
#[test]
fn every_terminal_and_recovery_state_is_explained_actionably() {
    let output = cli(&["states"]);
    assert!(output.status, "states failed: {}", output.stderr);
    let text = &output.stdout;

    for state in [
        "terminal.completed",
        "terminal.cancelled",
        "terminal.unsupported",
        "terminal.rolled_back",
        "terminal.manual_recovery",
        "recovery.rollback_required",
    ] {
        assert!(text.contains(state), "missing {state}");
    }

    // The safe-abort states say the disk is untouched.
    assert!(text.contains("The disk is untouched"));
    assert!(text.contains("Nothing was changed"));
    // Rollback says Windows was restored.
    assert!(text.contains("Windows was restored"));
    // Manual recovery says explicitly not to retry, which is the one case where
    // a well-meaning retry could make things worse.
    assert!(
        text.contains("Do not retry"),
        "manual recovery must tell the operator not to retry"
    );
}

/// `explain` describes an arbitrary state and refuses an unknown one.
#[test]
fn explain_describes_a_state_and_refuses_an_unknown_one() {
    let output = cli(&["explain", "windows.bitlocker_prepared"]);
    assert!(output.status, "explain failed: {}", output.stderr);
    assert!(output.stdout.contains("windows.bitlocker_prepared"));
    assert!(output.stdout.contains("phase:"));
    assert!(output.stdout.contains("what now:"));
    // Non-terminal states list their legal next events from the graph.
    assert!(output.stdout.contains("Legal next events"));

    let output = cli(&["explain", "not.a.real.state"]);
    assert!(!output.status);
    assert!(
        output
            .stderr
            .contains("not a state in the executable graph")
    );
}

/// The CLI exposes no way to name a real disk, device, or production mode.
/// This is the operator-visible half of the "production mutation is unreachable"
/// guarantee.
#[test]
fn the_cli_exposes_no_production_or_device_target() {
    let output = cli(&[]);
    assert!(output.status);
    let usage = &output.stdout;
    assert!(usage.contains("cannot mutate a real machine"));
    for forbidden in ["--device", "--disk", "--production", "/dev/"] {
        assert!(
            !usage.contains(forbidden),
            "usage must not offer {forbidden}"
        );
    }

    // An unknown subcommand prints usage rather than doing anything.
    let output = cli(&["--device", "/dev/sda"]);
    assert!(output.status);
    assert!(output.stdout.contains("usage:"));

    // The source itself contains no device path or production constructor.
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/jstack-installer.rs"),
    )
    .unwrap();
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("/dev/"),
        "the CLI may not name a device path"
    );
    assert!(
        code.contains("EffectBoundary::virtual_platform"),
        "the CLI must use the sealed virtual boundary"
    );
    // The only boundary constructor in the file is the virtual one.
    assert_eq!(
        code.matches("EffectBoundary::").count(),
        1,
        "the CLI must construct exactly one kind of effect boundary"
    );
}

/// Byte formatting always shows the exact value alongside the human one for the
/// interval, because an approximate size must never be the only thing shown.
#[test]
fn sizes_are_shown_in_both_exact_and_human_terms() {
    let output = cli(&["confirm", &plan(), &display()]);
    assert!(output.status);
    // The interval lines carry both representations.
    assert!(output.stdout.contains("byte 387101753344 (360.51 GiB)"));
    assert!(output.stdout.contains("byte 430051426304 (400.51 GiB)"));
}
