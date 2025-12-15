# VMware Fusion ARM Setup for Darkly (Mac M1)

## Why VMware Fusion?

- ✅ **Works better than UTM** for x86 emulation on M1
- ✅ **Free for students**
- ✅ **More stable boot process**
- ✅ **Better BIOS support**

## Step-by-Step Installation

### 1. Download VMware Fusion

1. **Visit:** https://www.vmware.com/products/fusion/fusion-evaluation.html

2. **Important:** Make sure you download the **ARM version** (for Apple Silicon)
   - It should say "for Apple Silicon" or "ARM"
   - NOT the Intel version

3. **Download the .dmg file**

4. **Install:**
   - Open the .dmg
   - Drag VMware Fusion to Applications
   - Open it from Applications

### 2. Get License (Free)

1. **Personal Use License (Free):**
   - VMware Fusion is free for personal use
   - Just accept the license

2. **Student License (Also Free):**
   - If you're a student, you can get additional features
   - Visit: https://www.vmware.com/academic/students.html

### 3. Create the Darkly VM

1. **Open VMware Fusion**

2. **File → New** (or click "New" button)

3. **Select "Create a custom virtual machine"**
   - Don't use "Install from disc or image" - use custom

4. **Operating System:**
   - Select **"Linux"**
   - Version: **"Other Linux 5.x kernel 64-bit"**
   - If that doesn't work, try: **"Other Linux 3.x kernel 64-bit"**
   - Click **Continue**

5. **Firmware (CRITICAL!):**
   - Select **"BIOS"** (NOT UEFI)
   - This is the most important step!
   - Click **Continue**

6. **Virtual Hard Disk:**
   - Select **"Create a new virtual disk"**
   - Size: **8 GB** (minimum, can be more)
   - Click **Continue**

7. **Finish:**
   - Name: `Darkly`
   - Click **Finish**

### 4. Configure the VM (Before First Boot)

**DO NOT START THE VM YET!**

1. **Select your "Darkly" VM** in the list

2. **Click "Settings"** (gear icon) or right-click → Settings

3. **Memory:**
   - Set to **2048 MB** (2 GB)
   - More is better for x86 emulation

4. **Processors:**
   - Set to **2 cores**
   - Can try 4 if you have a powerful M1

5. **CD/DVD (IDE):**
   - Check **"Connect CD/DVD Drive"**
   - Select **"Use a disc image file"**
   - Click **"Choose a disc image..."**
   - Select your **Darkly ISO file**
   - Make sure it shows your ISO filename

6. **Network Adapter:**
   - Should be **"NAT"** (default)
   - This allows the VM to get an IP address

7. **Advanced Settings:**
   - Click **"Advanced"** button
   - Look for **"Firmware"** or **"Boot"** options
   - Ensure it's set to **BIOS** (not UEFI)

8. **Click "Show All"** to go back

9. **Click "Lock"** icon to save settings

### 5. Start the VM

1. **Select "Darkly" VM**

2. **Click the Play button** (▶️) or **Power On**

3. **Wait for boot:**
   - May take 2-3 minutes (x86 emulation is slower)
   - You should see boot messages
   - Eventually, you should see the IP address

4. **Note the IP address** displayed on screen

5. **Open browser** and go to: `http://[IP_ADDRESS]`

## Troubleshooting VMware Fusion

### "VM won't start"
- Check you have the ARM version (not Intel)
- Try increasing memory to 2048 MB
- Check ISO is properly mounted

### "Stuck at boot" or "Kernel panic"
- Verify firmware is set to **BIOS** (not UEFI)
- Try different Linux version (3.x vs 5.x)
- Check ISO file is not corrupted

### "No IP address shown"
- Wait longer (boot can be slow with emulation)
- Check network adapter is enabled
- Try: In VM, open terminal and type `ifconfig`

### "Very slow"
- Normal for x86 emulation on M1
- Be patient
- Can try increasing CPU cores to 4

### "Can't find ISO"
- Make sure ISO path is correct
- Try copying ISO to Desktop first
- Re-select the ISO in CD/DVD settings

## Key Settings Summary

**Critical Settings:**
- ✅ Firmware: **BIOS** (NOT UEFI)
- ✅ Memory: **2048 MB** minimum
- ✅ CD/DVD: **ISO file mounted**
- ✅ Network: **NAT**
- ✅ Linux Version: **Other Linux 5.x or 3.x**

## Comparison: UTM vs VMware Fusion

| Feature | UTM | VMware Fusion ARM |
|---------|-----|-------------------|
| Cost | Free | Free (personal/student) |
| x86 Emulation | Good | Better |
| BIOS Support | Sometimes tricky | More reliable |
| Ease of Use | Easy | Easy |
| Performance | Good | Better |
| Stability | Good | Better |

**Verdict:** VMware Fusion ARM is often more reliable for x86 ISOs on M1.

## If VMware Fusion Also Doesn't Work

1. **Check the ISO file:**
   - Is it the correct file?
   - Is it complete?
   - Can you verify it's not corrupted?

2. **Try Parallels Desktop** (if available):
   - Best performance
   - Most reliable
   - Has free trial

3. **Contact your school:**
   - They may have M1-specific instructions
   - They might provide alternative setup

---

**This should work!** VMware Fusion ARM is generally more reliable than UTM for this use case.

