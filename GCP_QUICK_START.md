# Google Cloud Platform - Quick Start for Darkly

## Fastest Way to Run Darkly ISO Online

### Prerequisites
- Google account
- Darkly ISO file
- 30-60 minutes for setup

## Step 1: Create GCP Account (5 minutes)

1. **Go to:** https://cloud.google.com/
2. **Click "Get started for free"**
3. **Sign in** with Google account
4. **Enter payment info** (won't be charged, free tier available)
5. **Get $300 free credit** (valid for 90 days)

## Step 2: Create Project (2 minutes)

1. **Go to:** https://console.cloud.google.com/
2. **Click project dropdown** (top left)
3. **Click "New Project"**
4. **Name:** `darkly-project`
5. **Click "Create"**

## Step 3: Enable Compute Engine (1 minute)

1. **Go to:** Compute Engine → VM instances
2. **Click "Enable"** if prompted
3. Wait for API to enable (~1 minute)

## Step 4: Upload ISO as Image (15-30 minutes)

### Option A: Using gcloud CLI (Recommended)

1. **Install gcloud CLI on your Mac:**
   ```bash
   # Using Homebrew
   brew install --cask google-cloud-sdk
   ```

2. **Initialize:**
   ```bash
   gcloud init
   # Select your project
   # Login with your Google account
   ```

3. **Upload ISO:**
   ```bash
   # Create a bucket first
   gsutil mb gs://darkly-iso-bucket
   
   # Upload ISO to bucket
   gsutil cp /path/to/Darkly.iso gs://darkly-iso-bucket/
   
   # Create image from ISO
   gcloud compute images create darkly-image \
     --source-uri=gs://darkly-iso-bucket/Darkly.iso \
     --guest-os-features=UEFI_COMPATIBLE
   ```

### Option B: Using Console (Easier, but slower)

1. **Go to:** Compute Engine → Images
2. **Click "Create Image"**
3. **Name:** `darkly-image`
4. **Source:** 
   - Select "Upload a file"
   - Click "Browse"
   - Select your Darkly ISO
5. **Image type:** Leave default
6. **Click "Create"**
7. **Wait for upload** (15-30 minutes depending on ISO size)

## Step 5: Create VM Instance (2 minutes)

1. **Go to:** Compute Engine → VM instances
2. **Click "Create Instance"**

3. **Configure:**
   - **Name:** `darkly-vm`
   - **Region:** Choose closest to you
   - **Machine type:** 
     - **e2-micro** (free tier, but might be slow)
     - **e2-small** (better, ~$10/month)
   
4. **Boot disk:**
   - Click "Change"
   - **Source:** Custom images
   - **Image:** Select `darkly-image`
   - **Size:** 10 GB (minimum)
   - Click "Select"

5. **Firewall:**
   - ✅ Check "Allow HTTP traffic"
   - ✅ Check "Allow HTTPS traffic"

6. **Click "Create"**

7. **Wait for VM to start** (~1-2 minutes)

## Step 6: Get IP Address and Access (1 minute)

1. **In VM instances list:**
   - Find your `darkly-vm`
   - Note the **External IP** address
   - Example: `34.123.45.67`

2. **Access website:**
   - Open browser
   - Go to: `http://[EXTERNAL_IP]`
   - Example: `http://34.123.45.67`

3. **If website doesn't load:**
   - Wait 1-2 minutes (VM might still be booting)
   - Check firewall rules allow HTTP
   - Try accessing via SSH first to check status

## Step 7: Access VM via Browser (Optional)

1. **In VM instances:**
   - Click on your VM name
   - Click "SSH" button (opens browser terminal)

2. **Check if services are running:**
   ```bash
   # Check network
   ifconfig
   
   # Check if web server is running
   ps aux | grep apache
   ps aux | grep nginx
   
   # Check listening ports
   netstat -tlnp
   ```

## Step 8: Configure Firewall (If Needed)

If website doesn't load:

1. **Go to:** VPC network → Firewall
2. **Click "Create Firewall Rule"**
3. **Name:** `allow-http-darkly`
4. **Direction:** Ingress
5. **Targets:** All instances
6. **Source IP ranges:** `0.0.0.0/0`
7. **Protocols and ports:** 
   - ✅ TCP
   - Port: `80`
8. **Click "Create"**

## Cost Management

### Free Tier:
- **e2-micro:** 1 instance per month (limited hours)
- **30 GB disk:** Free
- **1 GB network egress:** Free

### Estimated Monthly Cost (if not free tier):
- **e2-small:** ~$10-15/month
- **Storage:** ~$2/month
- **Network:** ~$1-5/month
- **Total:** ~$13-22/month

### To Minimize Cost:
1. **Stop VM when not using:**
   - Click VM → Stop
   - Only pay for storage when stopped
2. **Delete when done:**
   - Delete VM and image to avoid charges
3. **Use free tier:** e2-micro instance

## Troubleshooting

### "Image creation failed"
- ISO might be too large
- Try compressing or splitting
- Check ISO is valid

### "VM won't start"
- Check image was created successfully
- Try different machine type
- Check quotas/limits

### "Website not accessible"
- Check firewall rules
- Wait for VM to fully boot
- Check if web server is running (via SSH)

### "Out of quota"
- Free tier has limits
- Upgrade to paid account
- Or use different region

## Clean Up (When Done)

To avoid charges:

1. **Stop VM:**
   - Compute Engine → VM instances
   - Select VM → Stop

2. **Delete VM:**
   - Select VM → Delete

3. **Delete Image:**
   - Compute Engine → Images
   - Select image → Delete

4. **Delete bucket** (if created):
   - Cloud Storage → Buckets
   - Delete bucket

## Alternative: Use Pre-built Solution

If uploading ISO is too complex:

1. **Create regular Linux VM** (Ubuntu/Debian)
2. **SSH into it**
3. **Upload ISO via SCP:**
   ```bash
   scp Darkly.iso user@vm-ip:/tmp/
   ```
4. **Install QEMU:**
   ```bash
   sudo apt update
   sudo apt install qemu-system-x86
   ```
5. **Run ISO:**
   ```bash
   qemu-system-x86_64 -m 2048 -cdrom /tmp/Darkly.iso -boot d -netdev user,id=net0,hostfwd=tcp::8080-:80 -device virtio-net,netdev=net0
   ```
6. **Access:** `http://vm-external-ip:8080`

---

**This is a great solution if local VMs aren't working!** Just make sure your school allows it.

