# UTM Quick Fix - The Essential Steps

## The 3 Critical Settings That Fix 90% of Issues

### 1. Boot Mode: BIOS (NOT UEFI) ⚠️ MOST IMPORTANT!

**Where to find it:**
- Edit VM → **System** tab
- Look for **"Boot"**, **"Firmware"**, or **"Boot Mode"** dropdown
- **MUST be set to "BIOS"** (not UEFI)

**Why:** Most Linux ISOs need BIOS boot, not UEFI. This is the #1 cause of UEFI Shell issues.

### 2. Enable x86 Emulation ✅

**Where to find it:**
- Edit VM → **System** tab
- Look for **"Force x86_64 emulation"** checkbox
- **CHECK IT** ✅

**Why:** M1 Macs are ARM, but the ISO is likely x86. You need emulation.

### 3. Mount ISO Correctly 💿

**Where to find it:**
- Edit VM → **Drives** tab
- Click **"+"** → **"CD/DVD"**
- Browse and select your ISO
- Interface: **"IDE"** (try this first)

**Why:** The ISO needs to be mounted as a bootable CD/DVD drive.

## Quick Fix Steps (5 Minutes)

1. **Edit your VM** (pencil icon)

2. **System tab:**
   - Boot/Firmware: **BIOS** ← Change this!
   - Force x86_64 emulation: **CHECKED** ← Enable this!

3. **Drives tab:**
   - Add CD/DVD drive if not there
   - Select your ISO file
   - Interface: **IDE**

4. **Save**

5. **Start VM**

6. **Wait 2-5 minutes** (first boot is slow)

## Still Stuck in UEFI Shell?

**The boot mode is still wrong!**

- Go back to System tab
- Look VERY carefully for the boot/firmware option
- It might be hidden or named differently
- Try every dropdown/option until you find BIOS
- Some versions call it "Legacy Boot"

## Memory Tip

- Increase to **2048 MB** (2 GB) minimum
- More memory = better emulation performance

## Still Not Working?

Try these in order:

1. **Recreate VM from scratch** (delete and start over)
2. **Try SATA instead of IDE** for CD/DVD interface
3. **Update UTM** to latest version
4. **Try VMware Fusion** (see `VMWARE_FUSION_SETUP.md`)

---

**Remember: BIOS boot mode is the key!** That's what fixes the UEFI Shell issue.

