# Quick Start Guide for macOS

## ⚠️ IMPORTANT: Mac M1/M2/M3 Users

**If you have an Apple Silicon Mac (M1, M2, M3):**
- ❌ **VirtualBox does NOT work** on Apple Silicon
- ✅ **Use UTM instead** - See **[MAC_M1_SETUP.md](MAC_M1_SETUP.md)** for M1-specific instructions

**If you have an Intel Mac:**
- ✅ VirtualBox works fine - continue below

---

## Fastest Way to Get Started (VirtualBox - Intel Macs Only)

### 1. Install VirtualBox (5 minutes)

```bash
# Option A: Using Homebrew (if you have it)
brew install --cask virtualbox

# Option B: Download manually
# Visit: https://www.virtualbox.org/wiki/Downloads
# Download: "OS X hosts" version
# Install the .dmg file
```

### 2. Create the VM (2 minutes)

1. Open **VirtualBox**
2. Click **"New"** button
3. Fill in:
   - **Name:** `Darkly`
   - **Type:** `Linux`
   - **Version:** `Debian (64-bit)` or `Other Linux (64-bit)` or `Other Linux (32-bit)`
   - ⚠️ **Note:** If you only see 64-bit options, that's fine! The ISO will work with either.
4. Click **Next**
5. **Memory:** Set to `1024 MB` (1 GB)
6. Click **Next**
7. **Hard Disk:** Select **"Do not add a virtual hard disk"**
8. Click **Create**, then **Continue** if warned

### 3. Configure the VM (1 minute)

1. Select your **Darkly** VM
2. Click **Settings** (gear icon)
3. Go to **Storage** tab
4. Under **Controller: IDE**, click the empty disk icon
5. Click the **CD/DVD icon** on the right
6. Click **"Choose a disk file..."**
7. Select your **Darkly ISO file**
8. Click **OK**

### 4. Network Settings (30 seconds)

1. Still in **Settings**, go to **Network** tab
2. **Adapter 1** should be:
   - ✅ **Enabled** (checked)
   - **Attached to:** `NAT`
3. Click **OK**

### 5. Start and Access (1 minute)

1. Select **Darkly** VM
2. Click **Start** (green arrow)
3. Wait for boot (30-60 seconds)
4. **Look for the IP address** displayed on screen
   - Example: `192.168.56.101` or `10.0.2.15`
5. **Open Safari/Chrome/Firefox**
6. Type in address bar: `http://[IP_ADDRESS]`
   - Example: `http://192.168.56.101`
7. You should see the Darkly website! 🎉

## Alternative: UTM (Simpler, but less features)

### Install UTM

```bash
# Using Homebrew
brew install --cask utm

# Or download from Mac App Store
```

### Create VM in UTM

1. Open **UTM**
2. Click **"+"** → **"Virtualize"**
3. Select **"Linux"**
4. **Name:** `Darkly`
5. **Memory:** `1024 MB`
6. **Storage:** Select your ISO file
7. Click **Save**
8. Click **Play** button
9. Note the IP address and access in browser

## Troubleshooting

### "VirtualBox won't install"
- Go to **System Settings** → **Privacy & Security**
- Allow the installation if blocked
- You may need to allow it in **Security** settings

### "Can't see IP address"
- In the VM terminal, type: `ifconfig`
- Look for IP starting with `192.168` or `10.0`

### "Website won't load"
- Make sure VM is running
- Check IP address is correct
- Try: `ping [IP]` in Terminal
- Check firewall: **System Settings** → **Network** → **Firewall**

### "VM is very slow"
- Close other apps
- Increase RAM to 2048 MB if possible
- Enable hardware acceleration in VM settings

## Quick Commands

```bash
# Test if VM is reachable
ping [IP_ADDRESS]

# Test website with curl
curl http://[IP_ADDRESS]

# Check your Mac's network
ifconfig | grep "inet "
```

## Next Steps

Once the website loads:
1. ✅ Bookmark the IP address
2. ✅ Read `TESTING_GUIDE.md`
3. ✅ Start with reconnaissance
4. ✅ Use `PAYLOADS.md` for testing
5. ✅ Document findings in breach folders

## Need More Help?

See the detailed guide: **[VM_SETUP.md](VM_SETUP.md)**

---

**Pro Tip:** Take a snapshot after setup so you can restore if something breaks!

