# Complete UTM Fix Guide for Darkly

## Step-by-Step: Fix UTM from Scratch

Let's fix UTM properly. Follow these steps **exactly** in order.

## Part 1: Clean Start (Delete and Recreate)

### Step 1: Delete Current VM

1. **Open UTM**
2. **Select your "Darkly" VM** (if it exists)
3. **Right-click** → **Delete** (or press Delete key)
4. **Confirm deletion**
5. This gives us a clean slate

### Step 2: Verify Your ISO File

Before creating the VM, let's make sure your ISO is good:

```bash
# Open Terminal and check your ISO
cd ~/Desktop/School/darkly  # or wherever your ISO is
ls -lh *.iso

# Check file size (should be > 100 MB typically)
# Try to mount it
hdiutil mount /path/to/your/Darkly.iso
```

**Note the ISO file path** - you'll need it in a moment.

## Part 2: Create VM with Correct Settings

### Step 3: Create New VM

1. **Open UTM**
2. **Click the "+" button** (top left, or File → New)
3. **Select "Virtualize"** (NOT "Emulate")
4. Click **Continue**

### Step 4: Operating System Selection

1. **Select "Linux"**
2. Click **Continue**
3. **Select "Other"** or **"Generic"** (whichever appears)
4. Click **Continue**

### Step 5: Hardware Configuration

1. **Memory (RAM):**
   - Set to **2048 MB** (2 GB)
   - Use the slider or type directly
   - **More is better for x86 emulation**
2. **CPU Cores:**
   - Set to **2 cores**
   - Can try 4 if you have M1 Pro/Max/Ultra
3. Click **Continue**

### Step 6: Storage Configuration

1. **Enable "VirtIO"** (should be checked by default)
2. **Size:**
   - Set to **8 GB** minimum
   - Type: **8** in the box
   - Even though we're booting from ISO, having a disk helps
3. Click **Continue**

### Step 7: Shared Directory

1. **Click "Skip"** (we don't need this for now)
2. Or leave default and click **Continue**

### Step 8: Summary

1. **Name:** Type `Darkly`
2. **DO NOT CLICK "Save" YET!**
3. **Click "Edit"** or look for **"Advanced"** button
   - We need to configure boot settings BEFORE saving

## Part 3: Critical Configuration (MOST IMPORTANT!)

### Step 9: Configure Boot Settings

**This is the critical part that usually fixes the issue!**

1. **Before saving, look for these options:**

   - **"Edit"** button
   - **"Advanced"** button
   - Or settings icon

2. **If you already saved, that's okay:**

   - Select the VM
   - Click **"Edit"** (pencil icon)

3. **Go to "System" tab** (or "Boot" tab)

4. **Find "Boot" or "Firmware" setting:**

   - Look for dropdown that says "UEFI" or "BIOS"
   - **Change it to "BIOS"** (NOT UEFI)
   - This is the #1 fix!

5. **Look for "Architecture" or "Emulation":**

   - Find **"Force x86_64 emulation"** checkbox
   - **CHECK IT** ✅
   - This is needed for M1 Macs to run x86 ISOs

6. **If you see "CPU" options:**

   - Try setting to **"x86_64"** if available
   - Or leave default

7. **Click "Save"** (or "Done")

### Step 10: Mount the ISO

1. **Still in Edit mode** (or edit again)

2. **Go to "Drives" tab**

3. **Click the "+" button** (bottom left)

4. **Select "CD/DVD"**

5. **Click "Browse"** button

6. **Navigate to and select your Darkly ISO file**

7. **Interface setting:**

   - Try **"IDE"** first (most common)
   - If that doesn't work later, we'll try "SATA"

8. **Make sure it shows:**

   - Your ISO filename
   - Interface: IDE (or SATA)
   - Size: should show the ISO size

9. **Click "Save"** (or "Done")

## Part 4: Final Checks Before Booting

### Step 11: Verify All Settings

Before starting, verify:

**System Tab:**

- ✅ Boot/Firmware: **BIOS** (NOT UEFI)
- ✅ Force x86_64 emulation: **CHECKED**
- ✅ Memory: **2048 MB** (or more)

**Drives Tab:**

- ✅ CD/DVD drive exists
- ✅ Shows your ISO filename
- ✅ Interface: **IDE** (or SATA)

**Network Tab:**

- ✅ Network adapter is enabled
- ✅ Should be "Shared Network" or "NAT"

### Step 12: Start the VM

1. **Select "Darkly" VM**

2. **Click the Play button** (▶️)

3. **Wait patiently:**

   - First boot can take 2-5 minutes
   - x86 emulation on M1 is slower
   - You'll see boot messages scrolling

4. **What to expect:**

   - Boot messages (kernel loading, etc.)
   - Eventually: IP address displayed
   - Or a login prompt

5. **If you see UEFI Shell again:**
   - Stop the VM
   - Go back to Step 9
   - Make absolutely sure Boot is set to **BIOS**

## Part 5: Troubleshooting Specific Issues

### Issue: Still Stuck in UEFI Shell

**Solution:**

1. **Edit VM** → **System tab**
2. **Look VERY carefully** for boot/firmware option
3. In some UTM versions, it might be:
   - "Firmware" dropdown
   - "Boot Mode" dropdown
   - "UEFI Boot" checkbox (uncheck it)
4. **Must be BIOS, not UEFI**
5. Save and try again

### Issue: Black Screen / Nothing Happens

**Solutions:**

1. **Wait longer** (up to 5 minutes for first boot)
2. **Check if VM is actually running:**
   - Look for CPU usage in Activity Monitor
   - If CPU is active, it's working, just slow
3. **Try increasing memory to 4096 MB** (4 GB)
4. **Try different ISO interface:**
   - Edit → Drives → Change from IDE to SATA (or vice versa)

### Issue: "No bootable device"

**Solutions:**

1. **Verify ISO is mounted:**
   - Edit → Drives tab
   - Should see your ISO listed
   - If not, add it again
2. **Check ISO file:**
   - Make sure file isn't corrupted
   - Try re-downloading if needed
3. **Try different interface:**
   - Change from IDE to SATA
   - Or from SATA to IDE

### Issue: Very Slow / Freezing

**Solutions:**

1. **This is normal** for x86 emulation on M1
2. **Be patient** - first boot takes time
3. **Increase memory:**
   - Try 4096 MB (4 GB)
4. **Reduce CPU cores:**
   - Try 1 core instead of 2
   - Sometimes less is more with emulation

### Issue: Kernel Panic / Errors

**Solutions:**

1. **Verify x86 emulation is enabled:**
   - System tab → Force x86_64 emulation: CHECKED
2. **Try different Linux version:**
   - When creating VM, try "Debian" instead of "Other"
3. **Check ISO compatibility:**
   - Make sure ISO is for x86_64 architecture

## Part 6: Alternative UTM Settings to Try

If the above doesn't work, try these variations:

### Variation 1: Different Storage

1. **Edit VM** → **Drives tab**
2. **Remove the hard disk** (if you added one)
3. **Keep only the CD/DVD** with ISO
4. Some ISOs boot better without a hard disk

### Variation 2: Different Network

1. **Edit VM** → **Network tab**
2. **Try "Shared Network"** instead of default
3. Or try **"Bridged"** if available

### Variation 3: Different Boot Order

1. **Edit VM** → **System tab**
2. Look for **"Boot Order"** or similar
3. Make sure **CD/DVD is first**

### Variation 4: QEMU Options (Advanced)

1. **Edit VM** → Look for **"QEMU"** or **"Advanced"** tab
2. **Add custom QEMU arguments:**
   ```
   -boot d
   ```
   This forces boot from CD/DVD

## Part 7: Verify UTM Version

Make sure you have the latest UTM:

1. **Check version:**

   - UTM → About UTM
   - Should be 4.x or later

2. **Update if needed:**
   - Mac App Store → Updates
   - Or download from: https://mac.getutm.app/

## Part 8: Last Resort - Manual Boot in UEFI Shell

If you're STILL stuck in UEFI Shell, try manual boot:

1. **In UEFI Shell, type:**

   ```
   map
   ```

   This lists all drives

2. **Find the CDROM:**

   - Look for `fs0:`, `fs1:`, or `CDROM`

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

5. **Look for boot files:**

   - `\EFI\BOOT\bootx64.efi`
   - `\boot\grub\grub.efi`
   - `\isolinux\isolinux.bin`

6. **Try to boot:**
   ```
   \EFI\BOOT\bootx64.efi
   ```

**But really, switching to BIOS mode (Step 9) should fix this!**

## Quick Checklist

Before starting VM, verify:

- [ ] VM created fresh (deleted old one)
- [ ] Memory: 2048 MB or more
- [ ] Boot/Firmware: **BIOS** (NOT UEFI) ← CRITICAL!
- [ ] Force x86_64 emulation: **CHECKED** ← CRITICAL!
- [ ] ISO mounted in Drives tab
- [ ] ISO interface: IDE (or SATA)
- [ ] Network adapter enabled
- [ ] UTM is latest version

## Expected Result

When it works, you should see:

1. Boot messages scrolling
2. Kernel loading
3. Services starting
4. **IP address displayed** (something like `192.168.x.x` or `10.0.x.x`)
5. Or a login prompt

Then open browser: `http://[IP_ADDRESS]`

---

## Still Not Working?

If you've tried ALL of the above and it still doesn't work:

1. **Share these details:**

   - What happens when you start the VM?
   - What's in the System tab (boot/firmware setting)?
   - What's in the Drives tab (ISO mounted?)?
   - UTM version?

2. **Consider VMware Fusion:**

   - Often more reliable than UTM
   - See `VMWARE_FUSION_SETUP.md`

3. **Check ISO file:**
   - Is it the correct file?
   - Is it complete?
   - Can you verify it's not corrupted?

---

**The #1 fix is: Boot mode must be BIOS, not UEFI!** Make absolutely sure of this in Step 9.
