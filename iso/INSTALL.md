# Install Jstack OS from this USB

This clean Jstack USB can run a live Niri desktop and install Jstack onto a
blank internal disk without downloading packages. Nothing installs automatically.
The ordinary Arch Linux installer USB is a different image and cannot do this.

## Before you start

- Back up anything important. The selected target becomes a new Jstack system.
- This installer is for a blank whole internal disk, at least 32 GiB, on an
  x86-64 UEFI computer with Secure Boot disabled. Existing partitions or
  filesystem signatures are refused. There is no dual boot or upgrade mode.
- Keep the machine connected to power and leave this USB plugged in throughout
  installation. Do not suspend the live session while installing.
- No Ubuntu installation or network connection is required for installation.
- The USB itself, other removable/USB disks, and mounted/in-use disks cannot
  be selected as installation targets. Do not bypass these checks.
- Private-overlay/custom-credential images cannot be installation sources. Use
  a clean image so personal credentials are not copied to the installed system.

## Boot the USB on a Dell

1. Plug in the USB, power on the Dell, and press F12 for its one-time boot menu.
2. Choose the USB's UEFI entry. This image does not support Secure Boot. Before
   changing firmware settings on an encrypted machine, secure its recovery keys.
3. Choose "Jstack OS live desktop". Niri should start automatically.
4. If graphics fail, use "Jstack OS live console (GPU fallback)" or Ctrl+Alt+F2.
   The fallback deliberately skips Niri. A graphics fallback does not prove that
   graphics will work after installation.

The live account is jstack. It has passwordless sudo. The live session is
volatile: its changes disappear after reboot. Do not remove the boot USB yet.

## Read instructions or inspect disks

These instructions are available without internet:

    jstack-install-help

Press q to leave the help viewer. You can also read:

    cat /usr/share/doc/jstack-live/INSTALL.md

A copy is also on the USB filesystem at JSTACK-INSTALL.md, readable by mounting
the USB on another computer without booting it.

List candidate disks without modifying them:

    sudo jstack-install-live --list
    lsblk -o NAME,TRAN,SIZE,MODEL,SERIAL,FSTYPE,LABEL,MOUNTPOINTS

Do not guess that /dev/sda is the internal disk. Device names can change when
booting. Match the internal disk's model, serial, and capacity.

## Install permanently

Press Alt+Space for the application launcher, then choose "Install Jstack OS
(blank disk)". Or press Alt+Return for a terminal and run:

    sudo jstack-install-live

Follow the prompts to choose a blank internal disk and create your username,
hostname, and password. Carefully review the displayed target identity and type
the exact confirmation requested. Cancel if the target is not the intended disk.
There is no automatic "yes to everything" option.

The installer creates an EFI System Partition and a Btrfs filesystem with @,
@home, @log, and @pkg subvolumes. It copies the clean offline system, creates
your account, configures the bootloader, and generates an installed-system
initramfs. Wait for the explicit installation-success message.

On success:

1. Shut down the live system with `sudo poweroff`.
2. Remove the USB only after shutdown completes.
3. Power on and boot the internal disk. Use F12 if necessary to select it.
4. The installed system should start Niri and contain Jcode, Kitty, Foot,
   Waybar, and the other Jstack defaults. Connect to your network and configure
   your own Jcode authentication. No personal credentials are included.

Installed policy uses tty1 autologin and passwordless sudo for your user.
Disk encryption is not configured. This is not a locked-down multiuser setup.
The installer does not change firmware boot variables. It writes the standard
UEFI fallback loader at EFI/BOOT/BOOTX64.EFI on the internal disk's EFI partition.
If the firmware does not list the internal system automatically, use its
boot-from-file or add-boot-option interface to select that file. Do not reinstall
or format the disk merely because a firmware boot entry is missing.

## Refusals and failures

If a disk has old partitions or filesystem signatures, the installer refuses
it even if it has no bootable operating system. Do not erase it blindly. Review
its contents and obtain a backup before any separately authorized disk cleanup.

This live installer is not the Ubuntu transactional recovery installer. It has
no power-loss rollback or resumable deployment guarantee. If installation fails
or power is interrupted, the target may be incomplete. Keep the USB, record the
error, and do not assume the internal disk is bootable. Its partially created
partitions will be refused on a new attempt until deliberately cleaned after
review. Never clean the USB or another disk to bypass a refusal.

A successful VM test does not guarantee every Dell's graphics, Wi-Fi, audio,
suspend, or firmware behavior. Test the live desktop on your actual machine.
