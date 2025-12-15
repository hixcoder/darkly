# Troubleshooting: "No bootable option or device was found"

## The Problem

You're seeing:
- "BdsDxe: failed to load Boot0001 "UEFI VBOX CD-ROM""
- "BdsDxe: No bootable option or device was found."

This means VirtualBox can't find your ISO file to boot from.

## Solutions (Try in Order)

### Solution 1: Check ISO is Mounted Correctly

1. **Shut down the VM** (close the window or power off)

2. **Select your VM** in VirtualBox

3. **Go to Settings** → **Storage**

4. **Check the IDE Controller:**
   - Under "Controller: IDE", you should see a CD/DVD icon
   - It should show your ISO filename (e.g., "Darkly.iso")
   - If it says "Empty" or shows no file:
     - Click the **empty disk icon**
     - Click the **CD/DVD icon** on the right
     - Click **"Choose a disk file..."**
     - **Browse and select your ISO file**
     - Click **OK**

5. **Verify the path is correct:**
   - Make sure the ISO file actually exists at that location
   - Try selecting it again to confirm

### Solution 2: Change Boot Order

1. **Settings** → **System**

2. **Boot Order tab:**
   - Make sure **"Optical"** (CD/DVD) is checked
   - Move it to the **top** of the boot order (use arrows)
   - Uncheck "Hard Disk" temporarily if needed

3. **Click OK**

### Solution 3: Switch from UEFI to Legacy BIOS

The error mentions "BdsDxe" which is UEFI. Some ISOs need Legacy BIOS mode.

1. **Settings** → **System**

2. **Motherboard tab:**
   - **Uncheck** "Enable EFI (special OSes only)"
   - This switches to Legacy BIOS mode

3. **Click OK**

4. **Try booting again**

### Solution 4: Verify ISO File

1. **Check the ISO file exists:**
   ```bash
   ls -lh /path/to/your/Darkly.iso
   ```

2. **Check file size** (should be > 0):
   - If file is 0 bytes or missing, you need to download it again

3. **Try mounting it manually** (on Mac):
   ```bash
   hdiutil mount /path/to/Darkly.iso
   ```
   - If this fails, the ISO might be corrupted

### Solution 5: Re-add the ISO

1. **Settings** → **Storage**

2. **Remove the current ISO:**
   - Select the ISO in the storage tree
   - Click the **"Remove"** button (minus icon)

3. **Add it again:**
   - Click the **empty disk icon** under IDE Controller
   - Click **"Choose a disk file..."**
   - Select your ISO
   - Click **OK**

### Solution 6: Check VirtualBox Version

1. **VirtualBox** → **About VirtualBox**
   - Make sure you have a recent version
   - Update if needed

## Step-by-Step Fix (Most Common Solution)

Try this exact sequence:

1. **Power off the VM** completely

2. **Settings** → **System** → **Motherboard**
   - ✅ Uncheck "Enable EFI"
   - Click **OK**

3. **Settings** → **Storage**
   - Under "Controller: IDE"
   - Click the **empty disk icon**
   - Click **CD/DVD icon** on right
   - Click **"Choose a disk file..."**
   - Select your **Darkly ISO file**
   - Make sure it shows the filename
   - Click **OK**

4. **Settings** → **System** → **Boot Order**
   - Make sure **Optical** is first
   - Click **OK**

5. **Start the VM again**

## Still Not Working?

### Check These:

- [ ] ISO file path is correct and file exists
- [ ] ISO file is not corrupted (try downloading again)
- [ ] VirtualBox has permission to access the file
- [ ] You're using the correct ISO file (not a different one)
- [ ] VM is completely powered off before changing settings

### Alternative: Try Different VM Type

If nothing works, try creating a new VM with:
- **Type:** Linux
- **Version:** `Other Linux (64-bit)` or `Other Linux (32-bit)`
- Make sure to mount the ISO before first boot

## Quick Checklist

Before booting, verify:
1. ✅ VM is powered off
2. ✅ ISO file is selected in Storage settings
3. ✅ Boot order has Optical first
4. ✅ EFI is disabled (for most ISOs)
5. ✅ ISO file path is valid

---

**Most likely fix:** Disable EFI (Solution 3) and ensure ISO is properly mounted (Solution 1).

