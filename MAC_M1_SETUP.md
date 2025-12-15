# Darkly Setup for Mac M1/M2/M3 (Apple Silicon)

## ⚠️ Important: VirtualBox Doesn't Work on Apple Silicon!

VirtualBox is x86-based and **does not support Apple Silicon Macs** (M1, M2, M3). You need to use a different virtualization tool.

## ✅ Recommended Solution: UTM (Free & Works Great on M1)

UTM is free, works natively on Apple Silicon, and can run x86 ISOs through emulation.

### Step 1: Install UTM

**Option A: Mac App Store (Easiest)**

1. Open **App Store**
2. Search for **"UTM"**
3. Click **"Get"** or **"Install"**

**Option B: Homebrew**

```bash
brew install --cask utm
```

**Option C: Direct Download**

- Visit: https://mac.getutm.app/
- Download the .dmg file
- Install it

### Step 2: Create the VM

1. **Open UTM**

2. **Click the "+" button** (or File → New)

3. **Select "Virtualize"** (not Emulate, unless you need x86 emulation)

4. **Operating System:**

   - Select **"Linux"**
   - Click **"Continue"**

5. **Linux:**

   - Select **"Other"** or **"Generic"**
   - Click **"Continue"**

6. **Hardware:**

   - **Memory:** Set to **1024 MB** (1 GB) or more
   - **CPU Cores:** 2 cores is fine
   - Click **"Continue"**

7. **Storage:**

   - **Enable "VirtIO"** (should be default)
   - **Size:** You can leave default or set to 8 GB
   - Click **"Continue"**

8. **Shared Directory:**

   - Skip this for now (click **"Skip"**)

9. **Summary:**
   - **Name:** `Darkly`
   - Click **"Save"**

### Step 3: Mount the ISO

1. **Select your "Darkly" VM** in UTM

2. **Click the "Edit" button** (pencil icon) or right-click → Edit

3. **Go to "Drives"** tab

4. **Click "+" to add a drive**

5. **Select "CD/DVD"**

6. **Click "Browse"** and select your **Darkly ISO file**

7. **Make sure "Interface" is set to "IDE"** or "SATA"

8. **Click "Save"**

### Step 4: Configure Boot Mode and x86 Emulation (IMPORTANT!)

**This is critical!** Many ISOs need BIOS boot mode, not UEFI:

1. **Edit the VM** (pencil icon)

2. **Go to "System"** tab

3. **Change Boot/Firmware:**

   - Look for **"Boot"** or **"Firmware"** option
   - Change from **"UEFI"** to **"BIOS"** or **"Legacy"**
   - ⚠️ **This is important!** Many ISOs won't boot in UEFI mode

4. **Enable x86 Emulation:**

   - ✅ **Check "Force x86_64 emulation"** (if your ISO is x86-based)
   - This is needed for M1 Macs to run x86 ISOs

5. **Click "Save"**

### Step 5: Start the VM

1. **Click the "Play" button** (▶️) on your Darkly VM

2. **Wait for boot** (may take a minute or two, especially with x86 emulation)

3. **Look for the IP address** displayed on screen

4. **Open your browser** and go to: `http://[IP_ADDRESS]`

## Alternative: VMware Fusion (ARM Version)

VMware Fusion has an ARM version that works on M1 Macs.

### Install VMware Fusion

1. **Download VMware Fusion** (ARM version):

   - Visit: https://www.vmware.com/products/fusion/fusion-evaluation.html
   - Make sure to get the **ARM version** (for Apple Silicon)
   - Students can get free license

2. **Install VMware Fusion**

### Create VM in VMware Fusion

1. **File → New**

2. **Select "Create a custom virtual machine"**

3. **Operating System:**

   - Select **"Linux"**
   - Version: **"Other Linux 5.x kernel 64-bit"** or **"Other Linux 3.x kernel 64-bit"**

4. **Firmware:**

   - Choose **"BIOS"** (not UEFI, unless the ISO specifically needs it)

5. **Finish**

6. **Settings:**

   - **Memory:** 1024 MB
   - **Processors:** 2 cores
   - **CD/DVD:** Select your ISO file
   - **Network:** NAT

7. **Start the VM**

## Alternative: Parallels Desktop (Paid, but Best Performance)

If you have Parallels Desktop (ARM version):

1. **File → New**

2. **Select "Install Windows, Linux, or another OS from a disc or image file"**

3. **Choose your ISO file**

4. **OS Type:** Select **"Linux"** → **"Other Linux"**

5. **Configure:**

   - **Memory:** 1024 MB
   - **CPU:** 2 cores

6. **Start**

## Performance Notes for M1 Macs

### With UTM (x86 Emulation):

- ⚠️ **Slower** - x86 emulation on ARM is slower
- ✅ **Free** - No cost
- ✅ **Works** - Will run the ISO, just be patient

### With VMware Fusion ARM:

- ✅ **Better performance** than UTM for x86
- ✅ **Free for students**
- ⚠️ **May still need emulation** for x86 ISOs

### With Parallels:

- ✅ **Best performance**
- ❌ **Paid** (but has trial)

## Troubleshooting for M1 Macs

### "VM won't start" or "Kernel panic"

- **Solution:** Enable x86 emulation in UTM settings
- Or try VMware Fusion instead

### "Very slow performance"

- **Normal** - x86 emulation on ARM is slower
- Be patient, it will work
- Consider allocating more RAM (2 GB instead of 1 GB)

### "Can't find ISO file"

- Make sure you selected the ISO in the VM settings
- Try copying the ISO to a simpler path (like Desktop)

### "Network not working"

- Check network adapter is enabled
- Try different network modes (NAT, Shared Network)

### "Stuck in UEFI Shell" or "Shell> prompt"

- **Solution:** Change boot mode from UEFI to BIOS in System settings
- See **[UTM_UEFI_FIX.md](UTM_UEFI_FIX.md)** for detailed fix

## Quick Start Checklist for M1

- [ ] Install UTM (or VMware Fusion ARM)
- [ ] Create new Linux VM
- [ ] Mount Darkly ISO file
- [ ] Enable x86 emulation (if needed)
- [ ] Start VM
- [ ] Note IP address
- [ ] Access website in browser

## Recommended Setup for M1

**Best option:** **UTM** with x86 emulation enabled

- Free
- Works reliably
- Just be patient with performance

**Steps:**

1. Install UTM from App Store
2. Create Linux VM
3. Enable x86 emulation in System settings
4. Mount ISO
5. Boot and wait (may take 2-3 minutes to boot)

---

**Remember:** On M1 Macs, you MUST use UTM, VMware Fusion ARM, or Parallels. VirtualBox will not work!
