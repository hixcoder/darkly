# Darkly Project Setup Guide (Apple Silicon / Mac M1-M3)

This guide documents the specific configuration required to run the **Darkly** project ISO on a Mac with Apple Silicon (M1, M2, M3) using UTM.

Since the project uses an older Linux kernel and x86 architecture, it cannot be "virtualized" natively on ARM chips. instead, it must be "emulated."

## Prerequisites

1.  **UTM App:** Download from [mac.getutm.app](https://mac.getutm.app/).
2.  **Darkly ISO:** The `.iso` file provided in the project resources.

## Configuration Steps

### 1. Create the Virtual Machine

- Open UTM and click **Create a New Virtual Machine**.
- Select **Emulate** (Do NOT select Virtualize).
- Select **Linux**.
- Click **Browse** and select your `Darkly.iso` file.

### 2. System Settings (Crucial)

Go to the **System** tab in the configuration menu.

- **Architecture:** Set to `x86_64`.
  - _Note: Even though the PDF mentions i386, the kernel inside the ISO is 64-bit and will panic if you use i386._
- **System:** Standard PC (i440FX is fine).
- **Memory:** `1024 MB` or `2048 MB` (The server is lightweight, 1GB is sufficient).

### 3. QEMU Settings (Boot Mode)

Go to the **QEMU** tab.

- **UEFI Boot:** **Unchecked** (Disabled).
  - _Reason: The ISO uses an old ISOLINUX bootloader that requires Legacy BIOS. It will not boot with UEFI enabled._

### 4. Display Settings (Fixing Black Screen)

Go to the **Display** tab.

- **Emulated Display Card:** Set to `VGA`.
  - _Reason: The default `virtio-ramfb` or `virtio-gpu` cards are too modern for this kernel. Using VGA fixes the "Display output is not active" error._

### 5. Network Settings

Go to the **Network** tab.

- **Network Mode:** `Emulated VLAN`.
  - _This allows the VM to get an IP address that you can access from your Mac's browser._

---

## How to Run

1.  Save the settings and **Start** the VM.
2.  Ignore the graphical "Don't Panic" screen; wait for the text console to appear.
3.  The VM will display a prompt similar to:
    ```
    WEB SECTION
    Good luck & Have fun
    To start the challenges, open your web browser (:80) and go to:
    192.168.64.X (or similar IP)
    ```
4.  Open **Safari** or **Chrome** on your Mac.
5.  Type the IP address shown in the VM into your address bar.

## Troubleshooting Summary

| Error Message                                                      | Cause                                                        | Solution                                |
| :----------------------------------------------------------------- | :----------------------------------------------------------- | :-------------------------------------- |
| **"Display output is not active"**                                 | The default graphics card is too new for the guest OS.       | Change Display Card to **VGA**.         |
| **"Kernel requires an x86-64 CPU, but only detected an i686 CPU"** | The VM architecture is set to 32-bit, but the ISO is 64-bit. | Change Architecture to **x86_64**.      |
| **Boot hangs or blinking cursor**                                  | UEFI is likely enabled.                                      | Uncheck **UEFI Boot** in QEMU settings. |
