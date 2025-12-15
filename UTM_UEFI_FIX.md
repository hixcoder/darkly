# Fix: UTM Stuck in UEFI Shell

## The Problem

Your VM booted into UEFI Shell instead of booting from the ISO. You see:
- `Shell>` prompt
- CDROM is detected (BLK1) but not booting

## Solution 1: Switch to BIOS/Legacy Boot (Recommended)

1. **Shut down the VM** (close the window or stop it)

2. **Select your "Darkly" VM** in UTM

3. **Click "Edit"** (pencil icon)

4. **Go to "System" tab**

5. **Look for "Boot" or "Firmware" settings:**
   - Change from **"UEFI"** to **"BIOS"** or **"Legacy"**
   - OR uncheck "UEFI Boot" if there's a checkbox

6. **Also check:**
   - ✅ **"Force x86_64 emulation"** should be checked (for x86 ISOs)
   - This is important for M1 Macs!

7. **Click "Save"**

8. **Start the VM again**

## Solution 2: Manually Boot from CDROM in UEFI Shell

If you're already in the UEFI shell, you can try to boot manually:

1. **In the UEFI Shell, type:**
   ```
   map
   ```
   This shows all available drives.

2. **Find the CDROM drive** (usually `fs0:` or `fs1:`)

3. **Try to access it:**
   ```
   fs0:
   ```
   or
   ```
   fs1:
   ```

4. **List files:**
   ```
   ls
   ```

5. **If you see boot files, try:**
   ```
   \EFI\BOOT\bootx64.efi
   ```
   or
   ```
   \boot\grub\grub.efi
   ```

**However, Solution 1 (switching to BIOS) is much easier and more reliable!**

## Solution 3: Check ISO Mounting

Make sure the ISO is properly mounted:

1. **Edit VM** → **"Drives" tab**

2. **Verify:**
   - There's a CD/DVD drive listed
   - It shows your ISO filename
   - Interface is set to **"IDE"** (not USB)

3. **If not mounted:**
   - Click **"+"** → **"CD/DVD"**
   - Browse and select your ISO
   - Set Interface to **"IDE"**
   - Click **"Save"**

## Step-by-Step Fix (Do This!)

1. **Stop the VM** (if running)

2. **Edit VM** → **"System" tab**

3. **Change these settings:**
   - **Boot:** Change to **"BIOS"** or **"Legacy"** (NOT UEFI)
   - ✅ **Check "Force x86_64 emulation"** (if available)

4. **Go to "Drives" tab:**
   - Verify ISO is mounted
   - Interface should be **"IDE"**

5. **Click "Save"**

6. **Start VM**

7. **It should boot from the ISO now!**

## Why This Happens

- UTM defaults to UEFI boot
- Many Linux ISOs (especially older ones) need BIOS/Legacy boot
- The ISO might not have UEFI boot files

## Still Not Working?

### Try These:

1. **Re-create the VM:**
   - Delete the current VM
   - Create a new one
   - **During creation**, look for boot/firmware options
   - Select **"BIOS"** from the start

2. **Check ISO file:**
   - Make sure it's not corrupted
   - Try downloading again if needed

3. **Try different ISO interface:**
   - In Drives tab, try changing from "IDE" to "SATA"
   - Or vice versa

4. **Increase memory:**
   - Try 2048 MB instead of 1024 MB

## Quick Checklist

Before starting VM:
- [ ] Boot mode is set to **BIOS** (not UEFI)
- [ ] x86 emulation is **enabled**
- [ ] ISO is mounted in **Drives** tab
- [ ] Interface is set to **IDE**
- [ ] VM is **stopped** before making changes

---

**Most likely fix:** Change boot mode from UEFI to BIOS in System settings!

