# 📘 Windows Privilege Escalation (OSCP Guide)

## **Chapter 1: Introduction to Privilege Escalation**

* **What is Privilege Escalation?**
  → When you hack into a system, you usually don’t start as an admin. You might have a **low-privilege user**. Privilege escalation means finding a way to become **Administrator / SYSTEM (highest privilege)**.
  → Think: “I got in, but now I want full control.”

* **Why is it important for OSCP?**

  * Most OSCP boxes require privesc.
  * Without it, you can’t dump hashes, access protected files, or get persistence.

* **Two types of Privilege Escalation:**

  1. **Vertical** → From low privilege (User) to high privilege (Admin/SYSTEM).
  2. **Horizontal** → Staying at the same level, but accessing other users’ data.

* **Mindset**: After getting initial access, always ask:

  * Who am I? (`whoami`)
  * What can I do? (`whoami /priv`)
  * Where am I? (`systeminfo`)
  * What is running? (`tasklist`)

---

## **Chapter 2: Windows Basics (OSCP Needed Only)**

Before escalation, understand some **Windows fundamentals**:

1. **Windows Accounts:**

   * **Administrator** → full control.
   * **SYSTEM** → even higher than admin, used by services.
   * **Users** → normal accounts with limited rights.

2. **Security Identifiers (SID):** Unique ID for each user. Example: `S-1-5-21-...-500` → Admin account.

3. **Important Files:**

   * `C:\Windows\System32\config\SAM` → stores user hashes.
   * `C:\Windows\System32\config\SYSTEM` → system secrets.
   * `C:\Users\` → user profiles, desktop files, creds.

4. **Windows Services:**

   * Background programs (like Linux daemons).
   * Run as SYSTEM or user. If misconfigured, they can be abused.

---

## **Chapter 3: Enumeration (The Key Step)**

Before exploiting, you **enumerate** the machine for misconfigurations.
👉 Tools to use:

* **Manual commands:**

  * `systeminfo` → OS version, hotfixes, architecture.
  * `whoami /priv` → check privileges.
  * `net user` → list users.
  * `tasklist /svc` → running services.
  * `wmic qfe` → list installed patches.
  * `icacls <file>` → check file permissions.

* **Automated scripts:**

  * `winPEAS.exe` → all-in-one enumeration.
  * `Seatbelt` → security checks.
  * `PowerUp.ps1` → PowerShell privilege escalation checks.

💡 OSCP tip: Run **winPEAS**, but also try **manual commands** because sometimes automation misses things.

---

## **Chapter 4: Common Privilege Escalation Techniques**

Here’s the **core** section you’ll use in OSCP.

### 1. **Kernel Exploits (Windows Version-based)**

* If the system is missing patches, you can use public exploits.
* Example:

  * `MS16-032` (Windows 7/8 Local Priv Esc).
  * `MS10-015` (older versions).
* Steps:

  1. Find OS version → `systeminfo`.
  2. Compare with exploit list (e.g., [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)).
  3. Compile & run exploit.

👉 Risk: Might crash the system. Use carefully.

---

### 2. **Unquoted Service Path**

* Some Windows services are started using unquoted paths:
  Example: `"C:\Program Files\My Service\service.exe"`
  If it’s unquoted, Windows may try:

  * `C:\Program.exe`
  * `C:\Program Files\My.exe`

👉 If you can place a malicious `.exe` in `C:\`, you can hijack the service.
Commands:

```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "Auto"
```

---

### 3. **Weak Service Permissions**

* Some services allow normal users to **modify service configuration**.
* Abuse: Replace the binary with your reverse shell.
  Command:

```powershell
sc qc <service_name>
accesschk64.exe -uwcqv <username> <service_name>
```

---

### 4. **AlwaysInstallElevated (MSI Abuse)**

* If this policy is enabled, any `.msi` package runs as SYSTEM.
  Check:

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

* If both are `1` → Jackpot 🎯
* Create malicious `.msi` with `msfvenom`.

---

### 5. **Credential Hunting**

* Search for passwords in:

  * `C:\Users\<user>\Desktop\`
  * `C:\Windows\Panther\Unattend.xml`
  * Registry (`reg query HKLM /f password /t REG_SZ /s`)
  * Saved WiFi creds (`netsh wlan show profile name=<SSID> key=clear`)

---

### 6. **DLL Hijacking**

* Some apps load DLLs from insecure locations.
* If you drop a malicious DLL, you can escalate.
  Check tools like `ProcMon` for missing DLLs.

---

### 7. **Scheduled Tasks**

* Check scheduled tasks:

  ```powershell
  schtasks /query /fo LIST /v
  ```
* If writable by user → replace binary.

---

### 8. **Privileges Abuse**

* If you have special privileges (`whoami /priv`):

  * `SeImpersonatePrivilege` → JuicyPotato / PrintSpoofer exploit.
  * `SeBackupPrivilege` → Read SAM file.
  * `SeDebugPrivilege` → Inject into processes.

---

## **Chapter 5: Advanced Tricks**

* **Token Impersonation** → Abuse high-privilege tokens in memory.
* **Pass-the-Hash** → Use stolen NTLM hashes instead of passwords.
* **Mimikatz** → Dump credentials from memory.
* **PrintSpoofer** → Abuse `SeImpersonatePrivilege` on modern Windows.
* **UAC Bypass** → Escalate from Administrator to SYSTEM.

---

## **Chapter 6: Practice Strategy (For OSCP)**

1. **Always start with enumeration.**

   * Run `winPEAS` + manual checks.

2. **Check Windows version.**

   * If old → kernel exploit.
   * If patched → misconfigurations.

3. **Check services and permissions.**

   * Unquoted paths, weak ACLs.

4. **Check registry + files for creds.**

5. **Check privileges.**

   * If `SeImpersonatePrivilege` → PrintSpoofer.

---

## **Chapter 7: Cheat Sheet for Exam**

* **Commands to always run first:**

  ```powershell
  whoami
  whoami /priv
  systeminfo
  net user
  ipconfig /all
  tasklist /svc
  wmic qfe
  ```

* **Tools to upload:**

  * `winPEAS.exe`
  * `accesschk.exe`
  * `PowerUp.ps1`
  * `PrintSpoofer.exe`

---

## **Chapter 8: Resources & Practice Labs**

* **HackTheBox (Windows machines)**: Optimum, Bastard, Blue, Active.
* **VulnHub Windows VMs**: e.g., Kioptrix Windows.
* **Privilege Escalation Playground:**

  * TryHackMe → “Windows PrivEsc Arena”.
  * Local VMs with old Windows.

---

# 📘 Chapter 1: Introduction to Privilege Escalation (Deep Explanation)

---

## 1. **What is Privilege Escalation?**

👉 Imagine you break into a Windows machine during OSCP:

* You got a **reverse shell** but only as a **normal user** (like `bob`).
* As `bob`, you can’t do much:

  * Can’t access `C:\Windows\System32\config\SAM` (where hashes live).
  * Can’t install drivers.
  * Can’t read admin’s files.

💡 Your goal = **become SYSTEM** (the most powerful account).

* SYSTEM > Administrator > Normal User.

---

## 2. **Why is Privilege Escalation Needed in OSCP?**

* OSCP exam boxes are often designed so:

  * Step 1: Initial foothold (web exploit, weak creds, etc.) → low-priv shell.
  * Step 2: Privilege escalation → admin/SYSTEM.
* Without escalation, you **won’t get root.txt (flag)** → no points.

Think of privesc as **“second stage of hacking.”**

---

## 3. **Types of Privilege Escalation**

1. **Vertical PrivEsc** → Go higher (User → Admin → SYSTEM).
   Example: Exploit weak service to run as SYSTEM.
2. **Horizontal PrivEsc** → Stay at same level but switch users.
   Example: You are `bob`, but you read `alice`’s files.

👉 In OSCP, vertical privesc is the main focus.

---

## 4. **Mindset for Privilege Escalation**

When you land on a Windows box, **always slow down and ask:**

1. **Who am I?**

   * `whoami`
   * `echo %username%`

2. **What am I allowed to do?**

   * `whoami /priv` → lists privileges like `SeImpersonatePrivilege`.

3. **Where am I?**

   * `systeminfo` → OS version, architecture (x86 or x64).
   * Helps decide kernel exploits.

4. **What is running?**

   * `tasklist /svc` → running services.
   * Maybe one is misconfigured.

5. **What’s installed?**

   * `wmic product get name,version`
   * Old apps may have known exploits.

💡 This is like detective work. You gather info → then pick the right attack.

---

## 5. **Privilege Escalation Categories**

You’ll explore them deeply in later chapters, but here’s the roadmap:

1. **Kernel Exploits** (missing patches).
2. **Service Exploits** (unquoted paths, weak permissions).
3. **Misconfigurations** (AlwaysInstallElevated, registry).
4. **Credentials Hunting** (in files, registry, memory).
5. **Privilege Abuse** (special privileges → SeImpersonate, SeBackup).
6. **Scheduled Tasks** (replace writable binary).

---

## 6. **What to Practice in Chapter 1**

Since you’re just starting, **practice the basics of enumeration**.
👉 Don’t jump into exploits yet. Just learn to “see the machine.”

### 📝 Practical Tasks

1. **Set up a Windows VM** (Windows 7 or 10 vulnerable build).

   * You can use VulnHub/THM/HTB boxes or create your own.

2. **Get a low-priv shell** (even local login is fine for practice).

3. **Run these commands & write down outputs:**

   ```powershell
   whoami
   whoami /priv
   systeminfo
   net user
   net localgroup administrators
   tasklist /svc
   wmic qfe
   ```

4. **Install & run winPEAS.exe**

   * See what info it collects. Compare with manual commands.

5. **Build a notebook (or Excel sheet):**

   * Column 1: Command.
   * Column 2: Output meaning.
   * Column 3: Possible privesc ideas.

---

## 7. **Mini Practice Example**

Imagine you run:

```
whoami → bob  
whoami /priv → SeImpersonatePrivilege: Enabled  
systeminfo → Windows 10, Build 1809  
```

* This tells you:

  * You’re a low-priv user (`bob`).
  * You have `SeImpersonatePrivilege` (powerful).
  * OS is 1809 (so maybe PrintSpoofer exploit works).

👉 Already you see a path → PrintSpoofer (but that’s for later chapters).

---

## 8. **How to Build Skills (Beginner → Advanced)**

1. **Week 1:** Only practice enumeration → get comfortable with commands.
2. **Week 2:** Understand different privilege escalation paths (service misconfigs, AlwaysInstallElevated, etc.).
3. **Week 3–4:** Combine enumeration → exploit → escalation.
4. **After 1 month:** You’ll be able to land on *any Windows box*, and think:
   “Okay, I know what to check first, then second, then third.”

---

✅ So, Chapter 1 is all about:

* Understanding what privesc is.
* Why OSCP requires it.
* Building the **right mindset**.
* Practicing **enumeration only** (no exploits yet).

---

