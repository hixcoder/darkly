# All VM Solutions for Mac M1/M2/M3

## Complete List of Working VM Solutions

### 1. ✅ UTM (Free) - What You're Using

- **Status:** Should work, but having boot issues
- **Cost:** Free
- **Performance:** Good with x86 emulation
- **Let's troubleshoot this more below**

### 2. ✅ VMware Fusion (ARM Version) - RECOMMENDED

- **Status:** Works great on M1
- **Cost:** Free for students
- **Performance:** Better than UTM for x86
- **Download:** https://www.vmware.com/products/fusion/fusion-evaluation.html
- **Make sure to get ARM version!**

### 3. ✅ Parallels Desktop (Best Performance)

- **Status:** Excellent on M1
- **Cost:** Paid (~$100/year, but has free trial)
- **Performance:** Best option
- **Download:** https://www.parallels.com/

### 4. ✅ QEMU (Command Line)

- **Status:** Works but complex
- **Cost:** Free
- **Performance:** Good
- **Complexity:** High (command-line only)

### 5. ❌ VirtualBox

- **Status:** Does NOT work on M1
- **Reason:** x86-only, no ARM support

## Detailed Troubleshooting UTM

Let's try to fix UTM step by step:

### Step 1: Verify ISO File

```bash
# Check if ISO exists and is valid
file /path/to/Darkly.iso

# Check file size (should be > 0)
ls -lh /path/to/Darkly.iso

# Try to mount it on Mac
hdiutil mount /path/to/Darkly.iso
```

### Step 2: Complete UTM Reset

1. **Delete the current VM** (we'll recreate it)

2. **Create NEW VM with these exact settings:**

   **a. New VM:**

   - Click "+" → "Virtualize"
   - Linux → Other/Generic

   **b. Hardware:**

   - Memory: **2048 MB** (2 GB - more is better)
   - CPU: **2 cores**

   **c. Storage:**

   - Create a disk: **8 GB** (even though ISO should boot, having a disk helps)
   - Interface: **VirtIO**

   **d. BEFORE SAVING - Go to Advanced:**

   - Look for "System" or "Boot" options
   - **Firmware:** Select **"BIOS"** (NOT UEFI)
   - **Architecture:** If option exists, try "x86_64" or leave default

   **e. Save the VM**

3. **Mount ISO:**

   - Edit VM → Drives tab
   - Add CD/DVD drive
   - Select ISO file
   - **Interface: IDE** (try this first)
   - Save

4. **System Settings (Edit VM → System):**

   - ✅ **Boot:** BIOS (not UEFI)
   - ✅ **Force x86_64 emulation:** CHECKED
   - ✅ **CPU:** x86_64 (if option exists)

5. **Start VM**

### Step 3: Try Different Boot Interfaces

If IDE doesn't work, try:

- **SATA** instead of IDE
- **USB** instead of IDE
- **VirtIO** (if available)

### Step 4: Check UTM Version

Make sure you have the latest UTM:

- App Store → Updates
- Or reinstall from: https://mac.getutm.app/

## VMware Fusion ARM - Detailed Setup

This is often more reliable than UTM. Let's set it up:

### Installation:

1. **Download VMware Fusion (ARM):**

   ```bash
   # Visit: https://www.vmware.com/products/fusion/fusion-evaluation.html
   # Make sure it says "for Apple Silicon" or "ARM"
   ```

2. **Install and get license:**
   - Students can get free license
   - Personal use is also free

### Create VM:

1. **File → New**

2. **"Create a custom virtual machine"**

3. **Operating System:**

   - Linux
   - **Version:** "Other Linux 5.x kernel 64-bit" or "Other Linux 3.x kernel 64-bit"

4. **Firmware:**

   - **BIOS** (NOT UEFI - this is critical!)

5. **Finish**

6. **Settings BEFORE first boot:**

   - **Memory:** 2048 MB
   - **Processors:** 2
   - **CD/DVD:** Select your ISO file
   - **Network:** NAT
   - **Display:** Can leave defaults

7. **Advanced Settings:**

   - Look for "Firmware" or "Boot" options
   - Ensure it's set to **BIOS**

8. **Start VM**

## Parallels Desktop Setup

If you have Parallels or want to try the trial:

1. **File → New**

2. **"Install Windows, Linux, or another OS from a disc or image file"**

3. **Select your ISO**

4. **OS Type:**

   - Linux → Other Linux

5. **Configure:**

   - Memory: 2048 MB
   - CPU: 2 cores

6. **Before starting, check:**

   - Hardware → Boot Order → Make sure CD/DVD is first
   - Hardware → Boot → Should be "BIOS" not "UEFI"

7. **Start**

## QEMU Command Line (Advanced)

If nothing else works, you can try QEMU directly:

```bash
# Install QEMU
brew install qemu

# Run the ISO
qemu-system-x86_64 \
  -m 2048 \
  -cdrom /path/to/Darkly.iso \
  -boot d \
  -netdev user,id=net0 \
  -device virtio-net,netdev=net0
```

This is more complex but gives you full control.

## What to Try Next

### Priority Order:

1. **Try VMware Fusion ARM** (most reliable)

   - Free for students
   - Better x86 emulation than UTM
   - More stable

2. **Recreate UTM VM with exact settings above**

   - Use BIOS (not UEFI)
   - 2 GB RAM
   - IDE interface for CD
   - x86 emulation enabled

3. **Try Parallels** (if you have it or want trial)

   - Best performance
   - Most reliable

4. **Check if ISO is the problem:**
   - Is the ISO file complete?
   - Can you verify it's not corrupted?
   - Do you have the right ISO file?

## Debugging: What's Actually Happening?

Let's understand the boot process:

### In UTM, when you start the VM:

1. **What do you see?**

   - UEFI Shell? → Need BIOS mode
   - Black screen? → May be booting, wait longer
   - Error messages? → Note them down
   - Nothing? → Check if VM is actually starting

2. **Check VM logs:**

   - In UTM, look for any error messages
   - Check Console app on Mac for UTM errors

3. **Try booting without ISO first:**
   - Remove ISO
   - Start VM
   - See what happens (should show "No bootable device")
   - This confirms VM is working
   - Then add ISO back

## Alternative: Ask Your School

If nothing works:

1. **Contact your school's IT support**

   - They may have M1-specific instructions
   - They might provide a different ISO
   - They might have a pre-configured VM

2. **Check if there's a Docker version:**

   - Some schools provide Docker alternatives
   - Ask if it's acceptable

3. **Use school computers:**
   - If available, use school lab computers (usually Intel)
   - VirtualBox will work there

## My Strong Recommendation

**Try VMware Fusion ARM next:**

1. It's free for students
2. More reliable than UTM for x86 emulation
3. Better BIOS support
4. Easier to configure

The setup is similar to UTM but often works when UTM doesn't.

---

**Next Step:** Try VMware Fusion ARM. If that doesn't work, we can try other solutions or investigate the ISO file itself.
