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


