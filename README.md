# Safe-Browsing-Browser-Extension-

# Browser Input Sanitizer & Sandbox Viewer – Installation Guide

This document explains **only the steps required to install and run the browser extension and backend**
The Extension folder is frentend where you want to use the Extension in Chrome or Edge the Backend folder is for backend vm to communicate with the Extension
## 1. System Requirements

* Linux (Ubuntu preferred)
* Python **3.9+**
* Google Chrome / Chromium browser
* Git

Install required system packages:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip git curl -y
```

---

## 2. Project Structure

```
project-root/
│
├── Extension/        # Browser extension files
├── backend/          # Flask backend + sandbox
│   ├── app.py
│   ├── start.sh
│   ├── requirements.txt
│   ├── uploads/
│   └── venv/
└── README.md
```

---

## 3. Backend Installation

### Step 1: Clone Repository

```bash
git clone <your-repository-url>
cd backend
```

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Python Libraries (Direct Install)

⚠️ ** Install libraries directly using pip:

```bash
pip install flask
pip install playwright
pip install beautifulsoup4
pip install requests
pip install werkzeug
```

After installing Playwright, install the browser:

```bash
playwright install chromium
```

---

## 4. Start Backend Server

### Step 1: Clone Repository

```bash
git clone <your-repository-url>
cd backend
```

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Python Libraries

```bash
pip install -r requirements.txt
```

Main libraries used:

* Flask
* Playwright
* BeautifulSoup4
* Requests
* Werkzeug

### Step 4: Install Playwright Browser

```bash
playwright install chromium
```

---

## 4. Start Backend Server

Make startup script executable:

```bash
chmod +x start.sh
```

Run backend:

```bash
./start.sh
```

Backend will run at:

```
http://127.0.0.1:8080
```

⚠️ **Keep backend running while using the extension**

---

## 5. Browser Extension Installation

1. Open Chrome and go to:

   ```
   chrome://extensions/
   ```
2. Enable **Developer mode** (top-right)
3. Click **Load unpacked**
4. Select the `Extension/` folder

The extension icon will appear in the toolbar.

---

## ⚠️ Important: Backend IP Configuration

If your backend is running on a **different machine or VM**, you must update the backend IP address in the extension files.

Update the backend IP / base URL in the following files:

* `Extension/analyzer.js`
* `Extension/popup.js`
* `Extension/sandbox.js`
* `Extension/viewer.js`
* `Extension/manifest.json`

### What to change

Replace the existing backend address (example):

```
http://127.0.0.1:8080
```

With your backend VM IP:

```
http://<BACKEND_VM_IP>:8080
```

Example:

```
http://192.168.1.114:8080
```

After changing the IP:

1. Save all files
2. Go to `chrome://extensions/`
3. Click **Reload** on the extension

---

## 6. Verify Setup

* Open any website
* Click the extension icon
* Enter test inputs in form fields
* Use **Link Analyzer / Sandbox / File Viewer**

If backend is running, all features will work.

---

## 7. Common Errors

**Backend not running**

* Sandbox and link analysis will not work

**Playwright error**

* Run:

```bash
playwright install chromium
```

**Permission denied (start.sh)**

```bash
chmod +x start.sh
```

---

## 8. Stop Backend

Press:

```
CTRL + C
```

Deactivate virtual environment:

```bash
deactivate
```

---

✅ Installation complete. The extension is ready to use.
everytime you should down the vm you need move to the backend directory and run ./start.sh again (cd backend --> ./start.sh) 
