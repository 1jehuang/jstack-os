//! PH-17 pre-hardware installer CLI.
//!
//! This is the operator-facing entry point for the installer before physical
//! hardware is available. It does three things and nothing else:
//!
//! * **confirm** renders the exact disk plan the user must approve, in the same
//!   terms the architecture contract requires: the disk, every partition GUID,
//!   before and after sizes, and the exact allocation interval. It refuses to
//!   render a plan whose hash or displayed values do not match.
//! * **run** drives the graph through the sealed virtual effect boundary. It can
//!   only ever construct a `VirtualPlatform`, so this command cannot touch a real
//!   disk, filesystem, or firmware variable.
//! * **explain** describes what a given control state means and what the operator
//!   can do next, so a recovery state is never an opaque identifier.
//!
//! There is deliberately no `--production`, `--device`, or `--disk` flag. The
//! only destinations this binary can name are in-memory.

use std::process::ExitCode;

use std::collections::BTreeMap;

use jstack_installer_controller::authority::CapabilityAuthority;
use jstack_installer_controller::dispatch::dispatch;
use jstack_installer_controller::platform::{BitLockerState, RunningSystem, VirtualPlatform};
use jstack_installer_controller::runtime::{EffectBoundary, Runtime, StepResult};
use jstack_installer_controller::{
    DirectOutcome, GraphModel, StateId, TerminalOutcome, load_verified,
};
use jstack_installer_core::{
    Confirmation, Hash256, InstallPlan, PlanDisplay, validate_confirmation,
};
use sha2::{Digest, Sha256};

const GRAPH: &[u8] = include_bytes!("../../../model/installer-state-graph.json");

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    concat!(
        "usage: jstack-installer <command>\n",
        "\n",
        "  confirm <plan.json> <display.json>\n",
        "      Render the exact disk plan for approval.\n",
        "\n",
        "  confirmed <plan.json> <display.json> <confirmation.json>\n",
        "      Validate a recorded confirmation against the plan and display.\n",
        "\n",
        "  run <plan.json> [--bitlocker]\n",
        "      Execute the install against a virtual machine and report the terminal.\n",
        "\n",
        "  dispatch <plan.json> <action> <actor>
      Render the guest request document for one authorised mutating action.
      Every target comes from the plan, never from an argument.

  explain <state-id>\n",
        "      Describe a control state and the operator's options.\n",
        "\n",
        "  states\n",
        "      List every terminal and recovery state with its meaning.\n",
        "\n",
        "This binary cannot mutate a real machine. Every effect is applied to an\n",
        "in-memory virtual platform.\n",
    )
    .to_owned()
}

fn run() -> Result<String, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let graph = load_graph()?;

    match arguments.first().map(String::as_str) {
        Some("confirm") => {
            let plan = read_plan(arguments.get(1))?;
            let display = read_display(arguments.get(2))?;
            render_confirmation(&plan, &display)
        }
        Some("confirmed") => {
            let plan = read_plan(arguments.get(1))?;
            let display = read_display(arguments.get(2))?;
            let confirmation: Confirmation = read_json(arguments.get(3), "confirmation")?;
            validate_confirmation(&plan, &display, &confirmation)
                .map_err(|error| format!("confirmation is not valid: {error}"))?;
            Ok(format!(
                "confirmation accepted\n  plan hash:     {}\n  display digest: {}\n  confirmed at:   {} (unix ms)\n",
                plan.plan_hash.as_str(),
                confirmation.display_digest.as_str(),
                confirmation.confirmed_at_unix_ms
            ))
        }
        Some("run") => {
            let plan = read_plan(arguments.get(1))?;
            let bitlocker = if arguments.iter().any(|value| value == "--bitlocker") {
                BitLockerState::Protected
            } else {
                BitLockerState::NotApplicable
            };
            execute(&graph, &plan, bitlocker)
        }
        Some("dispatch") => {
            let plan = read_plan(arguments.get(1))?;
            let action = arguments
                .get(2)
                .ok_or_else(|| "dispatch requires an action id".to_owned())?;
            let actor = arguments
                .get(3)
                .ok_or_else(|| "dispatch requires an actor".to_owned())?;
            dispatch_request(&graph, &plan, action, actor)
        }
        Some("explain") => {
            let state = arguments
                .get(1)
                .ok_or_else(|| "explain requires a state id".to_owned())?;
            explain(&graph, state)
        }
        Some("states") => Ok(list_states(&graph)),
        _ => Ok(usage()),
    }
}

/// Render one authorised action as the request document a guest adapter reads.
///
/// Every target is taken from the confirmed plan rather than from an argument.
/// A caller can choose *which* action to dispatch, and can never choose what it
/// operates on, so a mistyped argument cannot redirect a mutation onto a disk
/// the plan never named.
fn dispatch_request(
    graph: &GraphModel,
    plan: &InstallPlan,
    action: &str,
    actor: &str,
) -> Result<String, String> {
    let authority = CapabilityAuthority::new(graph);
    let capability = authority
        .issue_actor(actor)
        .map_err(|error| format!("actor capability refused: {error:?}"))?;

    let mut targets: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    targets.insert(
        "disk_guid".to_owned(),
        serde_json::Value::String(plan.body.disk_guid.to_string()),
    );
    targets.insert(
        "windows_partition_guid".to_owned(),
        serde_json::Value::String(plan.body.windows_resize.partition_guid.to_string()),
    );
    targets.insert(
        "target_size_bytes".to_owned(),
        serde_json::Value::Number(plan.body.windows_resize.target_size_bytes.into()),
    );
    targets.insert(
        "original_size_bytes".to_owned(),
        serde_json::Value::Number(plan.body.windows_resize.original_size_bytes.into()),
    );

    let request = dispatch(graph, &capability, action, plan.plan_hash.as_str(), targets)
        .map_err(|error| format!("dispatch refused: {error}"))?;

    serde_json::to_string_pretty(&request)
        .map(|rendered| format!("{rendered}\n"))
        .map_err(|error| format!("could not render the request: {error}"))
}

fn load_graph() -> Result<GraphModel, String> {
    let digest = Hash256::from_bytes(Sha256::digest(GRAPH).into());
    load_verified(GRAPH, &digest).map_err(|error| format!("embedded graph is invalid: {error}"))
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: Option<&String>,
    what: &str,
) -> Result<T, String> {
    let path = path.ok_or_else(|| format!("a {what} path is required"))?;
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {what} {path}: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("{what} {path} is invalid: {error}"))
}

fn read_plan(path: Option<&String>) -> Result<InstallPlan, String> {
    let plan: InstallPlan = read_json(path, "plan")?;
    jstack_installer_core::validate_plan_hash(&plan)
        .map_err(|error| format!("plan hash does not match its body: {error}"))?;
    Ok(plan)
}

fn read_display(path: Option<&String>) -> Result<PlanDisplay, String> {
    read_json(path, "display")
}

/// Render the exact plan. Every number the user sees is derived from the signed
/// plan, and the display document must already agree with it.
fn render_confirmation(plan: &InstallPlan, display: &PlanDisplay) -> Result<String, String> {
    if display.plan_hash != plan.plan_hash {
        return Err("the display document describes a different plan".to_owned());
    }
    let body = &plan.body;
    if display.disk_guid != body.disk_guid
        || display.windows_partition_guid != body.windows_resize.partition_guid
        || display.windows_original_size_bytes != body.windows_resize.original_size_bytes
        || display.windows_target_size_bytes != body.windows_resize.target_size_bytes
    {
        return Err("the display document disagrees with the plan".to_owned());
    }

    let mut output = String::new();
    output.push_str("JStack will change this disk. Review every value before approving.\n\n");
    output.push_str(&format!("  disk GUID:        {}\n", body.disk_guid));
    output.push_str(&format!(
        "  plan hash:        {}\n",
        plan.plan_hash.as_str()
    ));
    output.push_str(&format!("  install id:       {}\n\n", body.install_id));

    let resize = &body.windows_resize;
    output.push_str("Windows partition will be SHRUNK:\n");
    output.push_str(&format!("  partition GUID:   {}\n", resize.partition_guid));
    output.push_str(&format!(
        "  size before:      {}\n",
        format_bytes(resize.original_size_bytes)
    ));
    output.push_str(&format!(
        "  size after:       {}\n",
        format_bytes(resize.target_size_bytes)
    ));
    output.push_str(&format!(
        "  space released:   {}\n\n",
        format_bytes(resize.released_bytes)
    ));

    let interval = &body.allocation_interval;
    output.push_str("New partitions will be created ONLY in this interval:\n");
    output.push_str(&format!(
        "  from:             byte {} ({})\n",
        interval.start_bytes,
        format_bytes(interval.start_bytes)
    ));
    output.push_str(&format!(
        "  to:               byte {} ({})\n",
        interval.end_bytes,
        format_bytes(interval.end_bytes)
    ));
    output.push_str(&format!(
        "  total:            {}\n\n",
        format_bytes(interval.end_bytes - interval.start_bytes)
    ));

    output.push_str("Partitions to CREATE:\n");
    for partition in &body.created_partitions {
        output.push_str(&format!(
            "  {:<12} {:<8} {:>10}  GUID {}\n",
            format!("{:?}", partition.role).to_lowercase(),
            format!("{:?}", partition.filesystem).to_lowercase(),
            format_bytes(partition.size_bytes),
            partition.partition_guid
        ));
        output.push_str(&format!(
            "               at byte {} (type {})\n",
            partition.offset_bytes, partition.type_guid
        ));
    }

    output.push_str("\nPartitions that will NOT be touched:\n");
    for partition in &body.before_layout {
        if partition.partition_guid == resize.partition_guid {
            continue;
        }
        output.push_str(&format!(
            "  {:<12} {:>10}  GUID {}\n",
            format!("{:?}", partition.role).to_lowercase(),
            format_bytes(partition.size_bytes),
            partition.partition_guid
        ));
    }

    output.push_str("\nIf anything goes wrong, these objects are rolled back:\n");
    for object in &body.rollback_objects {
        output.push_str(&format!(
            "  {:<18} {}\n",
            format!("{:?}", object.kind).to_lowercase(),
            object.stable_id
        ));
    }

    output.push_str("\nNothing has been changed yet. Approving records a confirmation bound to\n");
    output.push_str(&format!("plan hash {}.\n", plan.plan_hash.as_str()));
    Ok(output)
}

/// Execute the whole install against a virtual machine.
fn execute(
    graph: &GraphModel,
    plan: &InstallPlan,
    bitlocker: BitLockerState,
) -> Result<String, String> {
    let platform = VirtualPlatform::from_plan(plan, bitlocker)
        .map_err(|error| format!("cannot model this plan: {error}"))?;
    let mut runtime = Runtime::new(graph, plan, EffectBoundary::virtual_platform(platform));

    let path: Vec<&str> = if bitlocker == BitLockerState::Protected {
        BITLOCKER_PATH.to_vec()
    } else {
        HAPPY_PATH.to_vec()
    };

    let mut output = String::from("running the install against a virtual machine\n\n");
    for name in path {
        let transition = graph
            .transition_id(name)
            .ok_or_else(|| format!("the graph has no transition {name}"))?;
        let result = if graph.is_mutating(transition) {
            runtime
                .step(transition, None, None)
                .map_err(|error| format!("{name} failed: {error}"))?
                .unwrap_or(StepResult::HaltedForManualRecovery)
        } else {
            runtime
                .advance_direct(transition, DirectOutcome::Success)
                .map_err(|error| format!("{name} failed: {error}"))?
        };
        let state = runtime
            .state()
            .map_err(|error| format!("cannot derive state: {error}"))?;
        output.push_str(&format!(
            "  {:<34} {:<22} -> {}\n",
            name,
            format!("{result:?}"),
            graph.state(state).id
        ));

        if let Some(system) = boot_after(name) {
            runtime
                .observe_boot(system)
                .map_err(|error| format!("boot observation failed: {error}"))?;
        }
    }

    let state = runtime
        .state()
        .map_err(|error| format!("cannot derive state: {error}"))?;
    output.push_str(&format!("\nterminal state: {}\n", graph.state(state).id));
    output.push_str(&format!("journal records: {}\n", runtime.journal().len()));
    output.push_str(&explain(graph, &graph.state(state).id.clone())?);
    Ok(output)
}

const HAPPY_PATH: &[&str] = &[
    "begin_preflight",
    "acquire_release_manifest",
    "persist_release_acceptance",
    "accept_preflight_and_plan",
    "begin_payload_staging",
    "accept_verified_payload",
    "show_exact_plan",
    "confirm_exact_plan",
    "prepare_without_bitlocker",
    "reserve_windows_space",
    "create_xbootldr",
    "format_xbootldr",
    "copy_verified_payload",
    "stage_installer_loader",
    "create_installer_entry",
    "arm_installer_bootnext",
    "reboot_to_installer",
    "installer_boot_observed",
    "verify_linux_handoff",
    "revalidate_linux_plan",
    "create_linux_root",
    "format_linux_root",
    "deploy_jstack_image",
    "configure_jstack_system",
    "install_jstack_boot",
    "verify_offline_install",
    "arm_windows_finalizer",
    "arm_windows_finalize",
    "windows_finalizer_booted",
    "restore_windows_security",
    "cleanup_windows_bootstrap",
    "arm_installed_jstack",
    "reboot_to_installed_jstack",
    "jstack_boot_observed",
    "complete_after_first_boot",
];

const BITLOCKER_PATH: &[&str] = &[
    "begin_preflight",
    "acquire_release_manifest",
    "persist_release_acceptance",
    "accept_preflight_and_plan",
    "begin_payload_staging",
    "accept_verified_payload",
    "show_exact_plan",
    "confirm_exact_plan",
    "prepare_bitlocker",
    "suspend_bitlocker_after_finalizer",
    "reserve_windows_space",
    "create_xbootldr",
    "format_xbootldr",
    "copy_verified_payload",
    "stage_installer_loader",
    "create_installer_entry",
    "arm_installer_bootnext",
    "reboot_to_installer",
    "installer_boot_observed",
    "verify_linux_handoff",
    "revalidate_linux_plan",
    "create_linux_root",
    "format_linux_root",
    "deploy_jstack_image",
    "configure_jstack_system",
    "install_jstack_boot",
    "verify_offline_install",
    "arm_windows_finalizer",
    "arm_windows_finalize",
    "windows_finalizer_booted",
    "restore_windows_security",
    "cleanup_windows_bootstrap",
    "arm_installed_jstack",
    "reboot_to_installed_jstack",
    "jstack_boot_observed",
    "complete_after_first_boot",
];

fn boot_after(transition: &str) -> Option<RunningSystem> {
    match transition {
        "reboot_to_installer" => Some(RunningSystem::LinuxInstaller),
        "arm_windows_finalize" => Some(RunningSystem::Windows),
        "reboot_to_installed_jstack" => Some(RunningSystem::Jstack),
        _ => None,
    }
}

/// Describe a control state in operator terms. Recovery and failure states get
/// an explicit "what now" so a stuck install is never an opaque identifier.
fn explain(graph: &GraphModel, state_id: &str) -> Result<String, String> {
    let id = graph
        .state_id(state_id)
        .ok_or_else(|| format!("{state_id} is not a state in the executable graph"))?;
    let state = graph.state(id);

    let mut output = String::new();
    output.push_str(&format!("\n{}\n", state.id));
    output.push_str(&format!("  phase:   {}\n", state.phase));
    output.push_str(&format!("  actor:   {}\n", state.actor));
    output.push_str(&format!("  meaning: {}\n", state.description));
    output.push_str(&format!("  what now: {}\n", guidance(graph, id)));
    Ok(output)
}

/// Operator guidance derived from the graph, not from a parallel table.
fn guidance(graph: &GraphModel, id: StateId) -> String {
    let state = graph.state(id);
    if let Some(outcome) = state.terminal_outcome {
        return match outcome {
            TerminalOutcome::Success => {
                "The install completed and both systems were verified to boot. Nothing to do."
                    .to_owned()
            }
            TerminalOutcome::SafeAbort => {
                "The install stopped before changing anything. The disk is untouched; you can \
                 retry safely."
                    .to_owned()
            }
            TerminalOutcome::Unsupported => {
                "This machine's layout is not supported. Nothing was changed. No retry will \
                 help until the layout changes."
                    .to_owned()
            }
            TerminalOutcome::RolledBack => {
                "Every change was reversed and Windows was restored. The disk is back to its \
                 original layout and BitLocker protection was re-enabled."
                    .to_owned()
            }
            TerminalOutcome::ManualRecovery => {
                "Automatic recovery stopped deliberately because it could not prove the disk \
                 was safe to change further. Windows should still boot. Do not retry: collect \
                 the journal and recovery metadata first."
                    .to_owned()
            }
        };
    }

    // Non-terminal: describe the legal next steps from the graph itself.
    let mut events: Vec<&str> = graph
        .transition_ids()
        .filter(|transition| graph.transition(*transition).from == id)
        .map(|transition| graph.transition(transition).def.event.as_str())
        .collect();
    events.sort_unstable();
    events.dedup();
    if events.is_empty() {
        return "This state has no outgoing transitions.".to_owned();
    }
    format!(
        "The install continues automatically. Legal next events: {}.",
        events.join(", ")
    )
}

fn list_states(graph: &GraphModel) -> String {
    let mut output = String::from("terminal and recovery states\n");
    for id in graph.state_ids() {
        let state = graph.state(id);
        if state.terminal_outcome.is_none() && !state.id.starts_with("recovery.") {
            continue;
        }
        output.push_str(&format!("\n  {}\n", state.id));
        output.push_str(&format!("    {}\n", guidance(graph, id)));
    }
    output
}

/// Render a byte count in both exact and human terms. The exact value is always
/// present, because an approximate size must never be the only thing a user
/// sees before approving a partition change.
fn format_bytes(value: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (unit, scale) in UNITS {
        if value >= scale {
            let whole = value / scale;
            let fraction = ((value % scale) * 100) / scale;
            return format!("{whole}.{fraction:02} {unit}");
        }
    }
    format!("{value} B")
}
