# Generated action catalog

Generated from `installer/model/installer-state-graph.json`. Do not edit manually.

| Action | Platform | Risk | Idempotency | Recovery | Description |
|---|---|---|---|---|---|
| `collect_inventory` | `windows` | `read_only` | `idempotent` | `retry` | Collect hardware, firmware, power, BitLocker, disk, partition, and boot inventory. |
| `compute_partition_plan` | `shared` | `read_only` | `idempotent` | `retry` | Compute an immutable plan using supported shrink bounds and stable GUIDs. |
| `download_release_manifest` | `windows` | `external_io` | `content_addressed` | `retry` | Download the signed release and channel manifest. |
| `download_payload` | `windows` | `external_io` | `content_addressed` | `retry` | Download content-addressed installer, UKI, image, and recovery chunks. |
| `verify_payload` | `shared` | `read_only` | `idempotent` | `retry` | Verify signatures, hashes, sizes, graph compatibility, and expiry. |
| `present_exact_plan` | `windows` | `read_only` | `idempotent` | `retry` | Display exact disk identity and before/after layout. |
| `record_plan_confirmation` | `windows` | `user_authorization` | `idempotent` | `retry` | Record explicit confirmation bound to the exact plan hash. |
| `register_windows_finalizer` | `windows` | `filesystem_mutation` | `idempotent` | `compensate` | Register the signed reboot finalizer and recovery entry. |
| `suspend_bitlocker` | `windows` | `security_mutation` | `reconcile_required` | `compensate` | Suspend BitLocker protectors with RebootCount 0 only after recovery material and the gated startup dispatcher are durable; explicit finalization or rollback restores protection. |
| `shrink_windows_ntfs` | `windows` | `disk_mutation` | `reconcile_required` | `reconcile_then_compensate` | Shrink the Windows partition and NTFS filesystem through the Windows Storage API. |
| `create_xbootldr_partition` | `windows` | `disk_mutation` | `reconcile_required` | `compensate` | Create the planned XBOOTLDR GPT partition inside confirmed free space. |
| `format_xbootldr_fat32` | `windows` | `filesystem_mutation` | `reconcile_required` | `compensate` | Format XBOOTLDR as FAT32 with the planned label and GUID. |
| `copy_payload_to_xbootldr` | `windows` | `filesystem_mutation` | `content_addressed` | `retry` | Copy and re-verify content-addressed payload chunks and handoff data. |
| `stage_namespaced_esp_loader` | `windows` | `boot_mutation` | `content_addressed` | `compensate` | Write only signed JStack loader files under the namespaced ESP path. |
| `create_installer_boot_entry` | `windows` | `boot_mutation` | `reconcile_required` | `compensate` | Create a UEFI boot entry for the signed JStack installer loader. |
| `set_installer_bootnext` | `windows` | `boot_mutation` | `reconcile_required` | `compensate` | Set BootNext to the verified installer boot entry. |
| `request_reboot` | `shared` | `reboot` | `reconcile_required` | `reconcile` | Request an orderly reboot after the next durable state and resume token are flushed. |
| `verify_handoff` | `linux` | `read_only` | `idempotent` | `retry` | Verify signed handoff, journal chain, release manifest, and actor transition. |
| `reinventory_and_revalidate_plan` | `linux` | `read_only` | `idempotent` | `retry` | Re-inventory GPT and require the confirmed plan fingerprint to match. |
| `create_root_partition` | `linux` | `disk_mutation` | `reconcile_required` | `compensate` | Create only the planned JStack root partition inside confirmed free space. |
| `format_root_btrfs` | `linux` | `filesystem_mutation` | `reconcile_required` | `compensate` | Create the planned Btrfs filesystem and subvolume layout. |
| `deploy_root_image` | `linux` | `filesystem_mutation` | `content_addressed` | `retry` | Deploy and content-verify the offline JStack root image. |
| `configure_installed_system` | `linux` | `filesystem_mutation` | `idempotent` | `retry` | Configure users, locale, Niri, networking, firmware, recovery, and first boot. |
| `install_jstack_boot_artifacts` | `linux` | `boot_mutation` | `content_addressed` | `compensate` | Install signed UKIs and boot metadata on XBOOTLDR. |
| `verify_installation` | `linux` | `read_only` | `idempotent` | `retry` | Mount and verify root, boot artifacts, manifests, and required services. |
| `arm_windows_finalizer` | `linux` | `boot_mutation` | `reconcile_required` | `compensate` | Set Windows as the next boot and record finalizer mode. |
| `verify_windows_after_install` | `windows` | `read_only` | `idempotent` | `retry` | Confirm Windows boot, volume identity, and planned JStack partitions. |
| `restore_bitlocker` | `windows` | `security_mutation` | `reconcile_required` | `retry` | Restore BitLocker protection when it was suspended. |
| `cleanup_windows_bootstrap` | `windows` | `filesystem_mutation` | `idempotent` | `retry` | Remove transient Windows bootstrap state while preserving recovery metadata. |
| `set_jstack_bootnext` | `windows` | `boot_mutation` | `reconcile_required` | `compensate` | Set BootNext to the verified installed JStack boot entry. |
| `verify_jstack_first_boot` | `jstack` | `read_only` | `idempotent` | `retry` | Verify root, boot, Niri session, networking, and recovery services. |
| `arm_windows_rollback` | `linux` | `boot_mutation` | `reconcile_required` | `reconcile` | Set Windows as next boot and mark the signed journal for rollback mode. |
| `remove_jstack_boot_entries` | `windows` | `boot_mutation` | `reconcile_required` | `retry` | Remove only boot entries created by this installation plan. |
| `remove_namespaced_esp_files` | `windows` | `filesystem_mutation` | `idempotent` | `retry` | Remove only ESP paths recorded as created by this plan. |
| `delete_jstack_partitions` | `windows` | `disk_mutation` | `reconcile_required` | `reconcile` | Delete only root and XBOOTLDR partitions whose GUIDs match the plan. |
| `expand_windows_ntfs` | `windows` | `disk_mutation` | `reconcile_required` | `reconcile` | Expand Windows into adjacent recovered space through the Windows Storage API. |
| `unregister_windows_finalizer` | `windows` | `filesystem_mutation` | `idempotent` | `retry` | Remove the signed finalizer task and rollback registration. |
