# Online VM Solutions for Darkly Project

## Yes! You Can Use Online VMs

This is actually a great solution for M1 Mac users struggling with local virtualization!

## Option 1: Google Cloud Platform (GCP) - RECOMMENDED

### Why GCP?

- ✅ **Free tier** available ($300 credit for new users)
- ✅ Easy to upload ISO
- ✅ Works from any browser
- ✅ Full control

### Setup Steps:

1. **Create GCP Account:**

   - Go to: https://cloud.google.com/
   - Sign up (free $300 credit)

2. **Create Compute Engine Instance:**

   - Go to Compute Engine → VM instances
   - Click "Create Instance"
   - **Machine type:** e2-micro (free tier) or e2-small
   - **Boot disk:**
     - Click "Change"
     - Select "Custom images"
     - We'll upload ISO as image (see step 3)
   - **Firewall:** Allow HTTP and HTTPS traffic
   - Click "Create"

3. **Upload ISO as Custom Image:**

   - Go to Compute Engine → Images
   - Click "Create Image"
   - **Source:** Upload file
   - Upload your Darkly ISO
   - **Image type:** Raw disk
   - Click "Create"
   - Wait for upload (can take 10-30 minutes)

4. **Create VM with Your Image:**

   - Create new VM instance
   - Boot disk: Select your uploaded Darkly image
   - Create and start

5. **Access:**
   - Use SSH in browser
   - Or set up VNC/RDP for GUI
   - Note the external IP address
   - Access website: `http://[EXTERNAL_IP]`

### Cost:

- **Free tier:** e2-micro instance (limited hours/month)
- **Paid:** ~$5-10/month for small instance

## Option 2: AWS (Amazon Web Services)

### Setup:

1. **Create AWS Account:**

   - Go to: https://aws.amazon.com/
   - Free tier available (12 months)

2. **Upload ISO to S3:**

   - Go to S3
   - Create bucket
   - Upload your ISO file

3. **Create EC2 Instance:**

   - Go to EC2 → Launch Instance
   - **AMI:** You'll need to convert ISO to AMI (more complex)
   - Or use existing Linux AMI and mount ISO

4. **Alternative: Use EC2 Instance Connect:**
   - Launch Linux instance
   - Upload ISO to instance
   - Use QEMU/KVM to run ISO in the cloud instance

### Cost:

- **Free tier:** t2.micro (750 hours/month free)
- **Paid:** ~$5-15/month

## Option 3: Azure (Microsoft)

### Setup:

1. **Create Azure Account:**

   - Go to: https://azure.microsoft.com/
   - Free $200 credit

2. **Upload ISO:**

   - Use Azure Storage
   - Upload ISO file

3. **Create VM:**
   - Create Virtual Machine
   - Use ISO as boot disk (requires conversion to VHD)

### Cost:

- **Free credit:** $200 for new users
- **Paid:** ~$10-20/month

## Option 4: Browser-Based VM Services

### a) OnWorks.net

1. **Go to:** https://www.onworks.net/
2. **Free online Linux VMs**
3. **Limitation:** Can't upload custom ISO easily
4. **Use case:** If you can extract web app from ISO

### b) CodeSandbox / Gitpod

- For web development
- **Not suitable** for full OS ISO

## Option 5: Remote Desktop to School Computer

### If Available:

1. **Ask your school:**

   - Do they provide remote desktop access?
   - Can you use lab computers remotely?
   - Many schools offer this

2. **Use:**
   - School's Windows/Linux machine
   - Run VirtualBox there (works on Intel)
   - Access via remote desktop

## Option 6: Rent a VPS (Virtual Private Server)

### Providers:

1. **DigitalOcean:**

   - $6/month for basic droplet
   - Can upload ISO and run with QEMU

2. **Linode:**

   - $5/month
   - Similar to DigitalOcean

3. **Vultr:**
   - $6/month
   - Good performance

### Setup VPS:

1. **Create account** and deploy Linux server
2. **SSH into server:**

   ```bash
   ssh root@your-server-ip
   ```

3. **Install QEMU:**

   ```bash
   # On Ubuntu/Debian
   apt update
   apt install qemu-system-x86_64
   ```

4. **Upload ISO:**

   ```bash
   # Use SCP from your Mac
   scp Darkly.iso root@your-server-ip:/root/
   ```

5. **Run VM on VPS:**

   ```bash
   qemu-system-x86_64 \
     -m 2048 \
     -cdrom /root/Darkly.iso \
     -boot d \
     -netdev user,id=net0,hostfwd=tcp::8080-:80 \
     -device virtio-net,netdev=net0 \
     -vnc :1
   ```

6. **Access via VNC:**
   - Use VNC viewer to connect
   - Or access website: `http://your-server-ip:8080`

## Option 7: Use GitHub Codespaces / Gitpod (Advanced)

- Can run Docker containers
- **Not ideal** for ISO booting
- Would need to extract web app

## Recommended Approach

### For Ease: **Google Cloud Platform**

**Why:**

- Easiest to upload ISO
- Good free tier
- Browser-based access
- Good documentation

**Steps Summary:**

1. Sign up for GCP (free $300 credit)
2. Upload ISO as custom image
3. Create VM with that image
4. Access via browser
5. Get IP address
6. Access website

### For Cost: **DigitalOcean / Vultr VPS**

**Why:**

- Cheaper ($5-6/month)
- Full control
- Can run QEMU directly
- Good performance

**Steps Summary:**

1. Create account
2. Deploy Linux server
3. Upload ISO via SCP
4. Install QEMU
5. Run VM
6. Access website

## Important Considerations

### ✅ Advantages:

- No local virtualization needed
- Works on any computer (even M1 Mac)
- Can access from anywhere
- Often faster than local emulation

### ⚠️ Disadvantages:

- **Cost** (though many have free tiers)
- **Internet required**
- **More complex setup**
- **May violate project rules** (check with school!)

## Check Project Rules First!

**⚠️ IMPORTANT:** Before using online VMs:

1. **Check the project requirements:**

   - Does it say you MUST use local VM?
   - Are there restrictions on cloud services?

2. **Ask your school:**

   - Is using cloud VMs allowed?
   - Do they have recommendations?

3. **For evaluation:**
   - You might need to demonstrate local setup
   - Or show you can run it locally

## Quick Start: GCP (Easiest)

1. **Sign up:** https://cloud.google.com/free
2. **Create project**
3. **Enable Compute Engine API**
4. **Go to:** Compute Engine → Images
5. **Create Image** → Upload your ISO
6. **Create VM** → Use your image
7. **Start VM** → Get IP address
8. **Access:** `http://[IP_ADDRESS]`

## Alternative: Ask School for Help

Many schools provide:

- Remote lab access
- Pre-configured VMs
- Alternative setup instructions for M1 Macs
- School cloud resources

**Don't hesitate to ask!**

---

## My Recommendation

**Try this order:**

1. **Ask your school** if they have M1-specific instructions or remote access
2. **Try GCP free tier** (easiest cloud option)
3. **Try VPS** (DigitalOcean/Vultr) if you want more control
4. **Keep trying UTM** in parallel (it should work with BIOS mode)

**The online VM approach is totally valid** if your school allows it!
