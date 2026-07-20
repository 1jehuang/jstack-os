use std::{env, fs, process::ExitCode};

use jstack_installer_core::{Inventory, PlanDisplay, ReleaseRequirements, create_install_plan};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let (display_only, inventory_path, requirements_path) = match args.as_slice() {
        [_, inventory, requirements] => (false, inventory.as_str(), requirements.as_str()),
        [_, flag, inventory, requirements] if flag == "--display" => {
            (true, inventory.as_str(), requirements.as_str())
        }
        _ => {
            eprintln!(
                "usage: jstack-plan [--display] <inventory.json> <release-requirements.json>"
            );
            return ExitCode::from(2);
        }
    };
    match run(inventory_path, requirements_path, display_only) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jstack-plan: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(
    inventory_path: &str,
    requirements_path: &str,
    display_only: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let inventory: Inventory = serde_json::from_slice(&fs::read(inventory_path)?)?;
    let requirements: ReleaseRequirements = serde_json::from_slice(&fs::read(requirements_path)?)?;
    let plan = create_install_plan(&inventory, &requirements)?;
    if display_only {
        Ok(serde_json::to_string_pretty(&PlanDisplay::from(&plan))?)
    } else {
        Ok(serde_json::to_string_pretty(&plan)?)
    }
}
