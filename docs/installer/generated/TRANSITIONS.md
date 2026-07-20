# Generated transition table

Generated from `installer/model/installer-state-graph.json`. Do not edit manually.

| Transition | From | To | Actor | Max risk | Guards | Failure target |
|---|---|---|---|---|---|---|
| `begin_preflight` | `windows.bootstrap_started` | `windows.staging_reconciled` | `windows_bootstrap` | `staging_mutation` | - | `terminal.manual_recovery` |
| `acquire_release_manifest` | `windows.staging_reconciled` | `windows.release_manifest_verified` | `windows_bootstrap` | `external_io` | - | `windows.release_acquisition_failed` |
| `mark_release_acquisition_failed` | `windows.staging_reconciled` | `windows.release_acquisition_failed` | `windows_bootstrap` | `read_only` | - | - |
| `retry_release_acquisition` | `windows.release_acquisition_failed` | `windows.staging_reconciled` | `windows_bootstrap` | `read_only` | - | - |
| `cancel_release_acquisition` | `windows.release_acquisition_failed` | `terminal.cancelled` | `windows_bootstrap` | `read_only` | - | - |
| `persist_release_acceptance` | `windows.release_manifest_verified` | `windows.preflight` | `windows_bootstrap` | `staging_mutation` | `release_candidate_valid` | `terminal.manual_recovery` |
| `abort_corrupt_release_acceptance` | `windows.release_manifest_verified` | `terminal.manual_recovery` | `windows_bootstrap` | `read_only` | - | - |
| `reject_unsupported_platform` | `windows.preflight` | `terminal.unsupported` | `windows_bootstrap` | `read_only` | - | - |
| `accept_preflight_and_plan` | `windows.preflight` | `windows.plan_computed` | `windows_bootstrap` | `read_only` | `running_as_admin`, `supported_windows`, `uefi_boot`, `gpt_basic_disk`, `single_system_disk`, `windows_ntfs_supported`, `windows_recovery_preserved`, `power_safe`, `windows_servicing_idle`, `storage_health_acceptable`, `enough_shrinkable_space`, `esp_has_loader_space`, `release_manifest_valid`, `boot_chain_trusted` | - |
| `begin_payload_staging` | `windows.plan_computed` | `windows.payload_staging` | `windows_bootstrap` | `staging_mutation` | `release_manifest_valid` | `windows.payload_invalid` |
| `accept_verified_payload` | `windows.payload_staging` | `windows.payload_verified` | `windows_bootstrap` | `staging_mutation` | `release_manifest_valid`, `boot_chain_trusted` | `windows.payload_invalid` |
| `mark_payload_invalid` | `windows.payload_staging` | `windows.payload_invalid` | `windows_bootstrap` | `read_only` | - | - |
| `retry_payload_download` | `windows.payload_invalid` | `windows.payload_staging` | `windows_bootstrap` | `read_only` | - | - |
| `cancel_invalid_payload` | `windows.payload_invalid` | `terminal.cancelled` | `windows_bootstrap` | `read_only` | - | - |
| `show_exact_plan` | `windows.payload_verified` | `windows.awaiting_confirmation` | `windows_bootstrap` | `read_only` | - | - |
| `cancel_before_mutation` | `windows.awaiting_confirmation` | `terminal.cancelled` | `windows_bootstrap` | `read_only` | - | - |
| `confirm_exact_plan` | `windows.awaiting_confirmation` | `windows.plan_confirmed` | `windows_bootstrap` | `user_authorization` | `plan_fingerprint_current` | - |
| `prepare_bitlocker` | `windows.plan_confirmed` | `windows.bitlocker_finalizer_registered` | `windows_bootstrap` | `filesystem_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `bitlocker_enabled`, `bitlocker_recovery_key_confirmed` | `recovery.rollback_required` |
| `suspend_bitlocker_after_finalizer` | `windows.bitlocker_finalizer_registered` | `windows.bitlocker_prepared` | `windows_bootstrap` | `security_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `bitlocker_enabled`, `bitlocker_recovery_key_confirmed`, `finalizer_registered` | `recovery.rollback_required` |
| `prepare_without_bitlocker` | `windows.plan_confirmed` | `windows.bitlocker_prepared` | `windows_bootstrap` | `filesystem_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `bitlocker_disabled` | `recovery.rollback_required` |
| `reserve_windows_space` | `windows.bitlocker_prepared` | `windows.space_reserved` | `windows_bootstrap` | `disk_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `windows_ntfs_supported`, `finalizer_registered` | `recovery.rollback_required` |
| `create_xbootldr` | `windows.space_reserved` | `windows.xbootldr_partition_created` | `windows_bootstrap` | `disk_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `planned_interval_current` | `recovery.rollback_required` |
| `format_xbootldr` | `windows.xbootldr_partition_created` | `windows.xbootldr_ready` | `windows_bootstrap` | `filesystem_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `planned_interval_current`, `xbootldr_partition_matches_plan` | `recovery.rollback_required` |
| `copy_verified_payload` | `windows.xbootldr_ready` | `windows.payload_staged` | `windows_bootstrap` | `filesystem_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `xbootldr_matches_plan`, `release_manifest_valid`, `staging_evidence_current` | `recovery.rollback_required` |
| `stage_installer_loader` | `windows.payload_staged` | `windows.installer_loader_files_staged` | `windows_bootstrap` | `boot_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `boot_chain_trusted`, `windows_boot_entry_present`, `staging_evidence_current` | `recovery.rollback_required` |
| `create_installer_entry` | `windows.installer_loader_files_staged` | `windows.installer_loader_staged` | `windows_bootstrap` | `boot_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `boot_chain_trusted`, `windows_boot_entry_present` | `recovery.rollback_required` |
| `arm_installer_bootnext` | `windows.installer_loader_staged` | `windows.bootnext_armed` | `windows_bootstrap` | `boot_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `boot_chain_trusted`, `windows_boot_entry_present`, `staging_evidence_current` | `recovery.rollback_required` |
| `reboot_to_installer` | `windows.bootnext_armed` | `windows.reboot_to_installer_pending` | `windows_bootstrap` | `reboot` | `confirmed_plan_current`, `plan_fingerprint_current`, `staging_evidence_current` | `windows.installer_rearm` |
| `installer_boot_observed` | `windows.reboot_to_installer_pending` | `linux.installer_booted` | `firmware` | `read_only` | - | - |
| `windows_resumed_instead` | `windows.reboot_to_installer_pending` | `windows.installer_rearm` | `windows_bootstrap` | `read_only` | `finalizer_not_armed` | - |
| `arm_installer_reboot_retry` | `windows.installer_rearm` | `windows.installer_rearm_armed` | `windows_bootstrap` | `boot_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `boot_chain_trusted`, `installer_rearm_not_attempted`, `finalizer_not_armed`, `staging_evidence_current` | `recovery.rollback_required` |
| `rearm_installer_boot` | `windows.installer_rearm_armed` | `windows.reboot_to_installer_pending` | `windows_bootstrap` | `reboot` | `confirmed_plan_current`, `plan_fingerprint_current` | `recovery.rollback_required` |
| `exhaust_installer_rearm` | `windows.installer_rearm` | `recovery.rollback_required` | `windows_bootstrap` | `read_only` | `installer_rearm_exhausted` | - |
| `reject_invalid_linux_handoff` | `linux.installer_booted` | `recovery.rollback_required` | `linux_installer` | `read_only` | - | - |
| `verify_linux_handoff` | `linux.installer_booted` | `linux.handoff_verified` | `linux_installer` | `read_only` | `handoff_signature_valid`, `release_manifest_valid`, `staging_evidence_current` | - |
| `revalidate_linux_plan` | `linux.handoff_verified` | `linux.plan_revalidated` | `linux_installer` | `read_only` | `confirmed_plan_current`, `plan_fingerprint_current`, `planned_interval_current`, `windows_boot_entry_present` | - |
| `reject_drifted_plan` | `linux.handoff_verified` | `recovery.rollback_required` | `linux_installer` | `read_only` | - | - |
| `create_linux_root` | `linux.plan_revalidated` | `linux.root_partition_ready` | `linux_installer` | `disk_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `planned_interval_current` | `recovery.rollback_required` |
| `format_linux_root` | `linux.root_partition_ready` | `linux.root_filesystem_ready` | `linux_installer` | `filesystem_mutation` | `confirmed_plan_current`, `plan_fingerprint_current` | `recovery.rollback_required` |
| `deploy_jstack_image` | `linux.root_filesystem_ready` | `linux.image_deployed` | `linux_installer` | `filesystem_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `staging_evidence_current` | `recovery.rollback_required` |
| `configure_jstack_system` | `linux.image_deployed` | `linux.system_configured` | `linux_installer` | `filesystem_mutation` | `confirmed_plan_current`, `plan_fingerprint_current` | `recovery.rollback_required` |
| `install_jstack_boot` | `linux.system_configured` | `linux.bootloader_ready` | `linux_installer` | `boot_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `boot_chain_trusted`, `xbootldr_matches_plan`, `staging_evidence_current` | `recovery.rollback_required` |
| `reject_invalid_offline_install` | `linux.bootloader_ready` | `recovery.rollback_required` | `linux_installer` | `read_only` | - | - |
| `verify_offline_install` | `linux.bootloader_ready` | `linux.install_verified` | `linux_installer` | `read_only` | `installed_system_valid`, `jstack_boot_entry_valid`, `windows_boot_entry_present` | - |
| `arm_windows_finalizer` | `linux.install_verified` | `linux.windows_finalizer_armed` | `linux_installer` | `boot_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `windows_boot_entry_present`, `finalizer_registered` | `recovery.rollback_required` |
| `arm_windows_finalize` | `linux.windows_finalizer_armed` | `linux.reboot_to_windows_pending` | `linux_installer` | `reboot` | `confirmed_plan_current`, `plan_fingerprint_current`, `windows_boot_entry_present`, `finalizer_registered` | `recovery.rollback_required` |
| `reject_missing_windows_finalizer` | `linux.reboot_to_windows_pending` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `current_platform_windows`, `rollback_permitted` | - |
| `windows_finalizer_booted` | `linux.reboot_to_windows_pending` | `windows.finalizer_running` | `windows_finalizer` | `read_only` | `finalizer_registered`, `windows_boot_entry_present` | - |
| `restore_windows_security` | `windows.finalizer_running` | `windows.security_restored` | `windows_finalizer` | `security_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `windows_boot_entry_present` | `terminal.manual_recovery` |
| `cleanup_windows_bootstrap` | `windows.security_restored` | `windows.bootstrap_cleaned` | `windows_finalizer` | `filesystem_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `windows_boot_entry_present`, `bitlocker_restored_or_not_applicable` | `terminal.manual_recovery` |
| `arm_installed_jstack` | `windows.bootstrap_cleaned` | `windows.jstack_boot_armed` | `windows_finalizer` | `boot_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `boot_chain_trusted`, `bitlocker_restored_or_not_applicable`, `jstack_boot_entry_valid`, `windows_boot_entry_present` | `terminal.manual_recovery` |
| `reboot_to_installed_jstack` | `windows.jstack_boot_armed` | `windows.reboot_to_jstack_pending` | `windows_finalizer` | `reboot` | `confirmed_plan_current`, `plan_fingerprint_current`, `bitlocker_restored_or_not_applicable` | `terminal.manual_recovery` |
| `jstack_boot_observed` | `windows.reboot_to_jstack_pending` | `jstack.first_boot` | `jstack_first_boot` | `read_only` | - | - |
| `reject_failed_first_boot` | `jstack.first_boot` | `recovery.rollback_required` | `jstack_first_boot` | `read_only` | `rollback_permitted` | - |
| `complete_after_first_boot` | `jstack.first_boot` | `terminal.completed` | `jstack_first_boot` | `read_only` | `jstack_boot_entry_valid`, `bitlocker_restored_or_not_applicable`, `windows_boot_entry_present` | - |
| `dispatch_rollback_windows` | `recovery.rollback_required` | `windows.rollback_running` | `recovery_controller` | `read_only` | `current_platform_windows`, `rollback_permitted`, `rollback_identity_current` | - |
| `dispatch_rollback_linux` | `recovery.rollback_required` | `linux.rollback_to_windows_pending` | `recovery_controller` | `boot_mutation` | `current_platform_linux`, `rollback_permitted`, `rollback_identity_current` | `terminal.manual_recovery` |
| `reboot_to_windows_rollback` | `linux.rollback_to_windows_pending` | `windows.rollback_running` | `linux_installer` | `reboot` | `windows_boot_entry_present`, `rollback_permitted`, `rollback_identity_current` | `terminal.manual_recovery` |
| `execute_windows_rollback` | `windows.rollback_running` | `windows.rollback_boot_entries_removed` | `windows_finalizer` | `boot_mutation` | `rollback_permitted`, `rollback_identity_current`, `windows_boot_entry_present` | `terminal.manual_recovery` |
| `rollback_remove_esp_files` | `windows.rollback_boot_entries_removed` | `windows.rollback_esp_cleaned` | `windows_finalizer` | `filesystem_mutation` | `rollback_permitted`, `rollback_identity_current`, `windows_boot_entry_present` | `terminal.manual_recovery` |
| `rollback_delete_partitions` | `windows.rollback_esp_cleaned` | `windows.rollback_partitions_deleted` | `windows_finalizer` | `disk_mutation` | `rollback_permitted`, `rollback_identity_current`, `windows_boot_entry_present` | `terminal.manual_recovery` |
| `rollback_expand_windows` | `windows.rollback_partitions_deleted` | `windows.rollback_ntfs_restored` | `windows_finalizer` | `disk_mutation` | `rollback_permitted`, `rollback_identity_current`, `windows_boot_entry_present` | `terminal.manual_recovery` |
| `rollback_restore_security` | `windows.rollback_ntfs_restored` | `windows.rollback_security_restored` | `windows_finalizer` | `security_mutation` | `rollback_permitted`, `rollback_identity_current`, `windows_boot_entry_present` | `terminal.manual_recovery` |
| `rollback_unregister_finalizer` | `windows.rollback_security_restored` | `terminal.rolled_back` | `windows_finalizer` | `filesystem_mutation` | `rollback_permitted`, `rollback_identity_current`, `windows_boot_entry_present` | `terminal.manual_recovery` |
| `stop_on_rollback_divergence` | `recovery.rollback_required` | `terminal.manual_recovery` | `recovery_controller` | `read_only` | - | - |
| `request_rollback_from_windows_bitlocker_prepared` | `windows.bitlocker_prepared` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_space_reserved` | `windows.space_reserved` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_xbootldr_ready` | `windows.xbootldr_ready` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_payload_staged` | `windows.payload_staged` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_installer_loader_staged` | `windows.installer_loader_staged` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_bootnext_armed` | `windows.bootnext_armed` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_installer_rearm` | `windows.installer_rearm` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_installer_booted` | `linux.installer_booted` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_handoff_verified` | `linux.handoff_verified` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_plan_revalidated` | `linux.plan_revalidated` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_root_partition_ready` | `linux.root_partition_ready` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_root_filesystem_ready` | `linux.root_filesystem_ready` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_image_deployed` | `linux.image_deployed` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_system_configured` | `linux.system_configured` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_bootloader_ready` | `linux.bootloader_ready` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_install_verified` | `linux.install_verified` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_bitlocker_finalizer_registered` | `windows.bitlocker_finalizer_registered` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_xbootldr_partition_created` | `windows.xbootldr_partition_created` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_installer_loader_files_staged` | `windows.installer_loader_files_staged` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_installer_rearm_armed` | `windows.installer_rearm_armed` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_linux_windows_finalizer_armed` | `linux.windows_finalizer_armed` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `windows_resumed_instead_of_jstack` | `windows.reboot_to_jstack_pending` | `windows.jstack_rearm` | `windows_finalizer` | `read_only` | `bitlocker_restored_or_not_applicable` | - |
| `arm_jstack_reboot_retry` | `windows.jstack_rearm` | `windows.jstack_rearm_armed` | `windows_finalizer` | `boot_mutation` | `confirmed_plan_current`, `plan_fingerprint_current`, `boot_chain_trusted`, `bitlocker_restored_or_not_applicable`, `jstack_boot_entry_valid`, `windows_boot_entry_present`, `jstack_rearm_not_attempted` | `terminal.manual_recovery` |
| `reboot_rearmed_jstack` | `windows.jstack_rearm_armed` | `windows.reboot_to_jstack_pending` | `windows_finalizer` | `reboot` | `confirmed_plan_current`, `plan_fingerprint_current`, `bitlocker_restored_or_not_applicable` | `terminal.manual_recovery` |
| `exhaust_jstack_rearm` | `windows.jstack_rearm` | `recovery.rollback_required` | `windows_finalizer` | `read_only` | `jstack_rearm_exhausted`, `rollback_permitted` | - |
| `request_rollback_from_windows_jstack_rearm` | `windows.jstack_rearm` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
| `request_rollback_from_windows_jstack_rearm_armed` | `windows.jstack_rearm_armed` | `recovery.rollback_required` | `recovery_controller` | `read_only` | `rollback_permitted` | - |
