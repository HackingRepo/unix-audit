#!/usr/bin/env python3
"""
Author: Ethc4 Anonymous
Legal Disclaimer: The script for education purpose only for increase security not for harmful activity Author not responsable for any illegal Usage
Description: The tool audit Debian based Linux system for any misconfiguration or vulnerability
"""
import os
import pwd,grp
import re
import shutil
import subprocess
class ColorInterface:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    DARKCYAN = '\033[36m'
    BLACK = '\033[30m'
    YELLOW = '\033[33m'
    BLACK = '\033[30m'
    BLACK = '\033[30m'
    MAGENTA = '\033[35m'
class BackgroundColorInterface:
    BACKGROUND_BLACK = '\033[40m'
    BACKGROUND_RED = '\033[41m'
    BACKGROUND_GREEN = '\033[42m'
    BACKGROUND_YELLOW = '\033[43m' # orange on some systems
    BACKGROUND_BLUE = '\033[44m'
    BACKGROUND_MAGENTA = '\033[45m'
    BACKGROUND_CYAN = '\033[46m'
    BACKGROUND_LIGHT_GRAY = '\third-party033[47m'
    BACKGROUND_DARK_GRAY = '\033[100m'
    BACKGROUND_BRIGHT_RED = '\033[101m'
    BACKGROUND_BRIGHT_GREEN = '\033[102m'
    BACKGROUND_BRIGHT_YELLOW = '\033[103m'
    BACKGROUND_BRIGHT_BLUE = '\033[104m'
    BACKGROUND_BRIGHT_MAGENTA = '\033[105m'
    BACKGROUND_BRIGHT_CYAN = '\033[106m'
    BACKGROUND_WHITE = '\033[107m'


class AuditScript:
    def __init__(self, path='/'):
        self.path = path
    def basic_info(self):
        print(f'{ColorInterface.OKBLUE}Basic Info: ')
        uname = os.uname()
        print(f'{ColorInterface.OKCYAN}======================================{ColorInterface.END}')
        print(f'{ColorInterface.OKGREEN}[+] Groups and users: {ColorInterface.END}')
        for p in pwd.getpwall():
          users_and_group = p[0], grp.getgrgid(p[3])[0]
          print(f'{ColorInterface.OKCYAN}{users_and_group}')
        print(f'{ColorInterface.OKGREEN}[+] System Information: {ColorInterface.END}')
        print(f'{ColorInterface.OKCYAN}{uname}{ColorInterface.END}')
    def system_info(self):
        print(f'{ColorInterface.OKBLUE}System Info: ')
        uname = subprocess.getoutput('uname -a')
        processor_type = subprocess.getoutput('uname -m')
        node_name = subprocess.getoutput('uname -n')
        kernel_release = subprocess.getoutput('uname -r')
        print(f'{ColorInterface.OKGREEN}[+] Kernel Info: {ColorInterface.END}')
        with open('/etc/os-release','r') as os_release:
            print(f'{os_release.readline()}')
            print(f'{os_release.readline()}')
            print(f'{os_release.readline()}')
            print(f'{os_release.readline()}')
            os_release.close()
        print(f'FULL INFO: {uname}')
        print(f'ARCH: {processor_type}')
        print(f'HOST: {node_name}')
        print(f'Kernel Release: {kernel_release}')
    def sudo_version(self):
        sudo_ver = subprocess.getoutput('sudo -V 2>/dev/null | grep "Sudo ver"')
        vuln_sudo_ver = subprocess.getoutput('sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"')
        cve_sudo_ver = subprocess.getoutput(
            'sudo -V | grep "Sudo ver" | grep -E "1\.9\.5p2|1\.8\.28"'
        )
        print(f'{ColorInterface.OKBLUE}Sudo Info: {ColorInterface.END}')
        print(sudo_ver)
        if vuln_sudo_ver:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] the sudo version Potentially vulnerable to privilege esclation see https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version{ColorInterface.END}')
        if cve_sudo_ver:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] the sudo version have large known exploit used for privilege escalation see https://exploit-db.com for more information')
        print(f'{BackgroundColorInterface.BACKGROUND_GREEN}[PATCHED] The sudo version is patched but this not signifient your system not vulnerble to privilege escalation because security 100% is impossible and no system invulnerable {ColorInterface.END}')
    def sudo_config(self):
        print(f'{ColorInterface.OKBLUE}Sudo misconfigurations: ')
        sudo_output = subprocess.getoutput('sudo -l')
        if 'NOPASSWD' in sudo_output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Potentially vulnerable this allow run command without user password can attacker obtain privileges escalation without known user password{ColorInterface.END}')
        if 'ALL=(ALL:ALL) ALL' in sudo_output or 'ALL=(ALL) NOPASSWD: ALL' in sudo_output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Full unrestricted sudo rights found. User can execute any command as root. If combined with NOPASSWD, this is extremely dangerous.{ColorInterface.END}')
        if not 'secure_path' in sudo_output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Vulnerable to path hijacking attack because not use secure_path{ColorInterface.END}')
        else:
            print(f'{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] No obvious sudo misconfigurations detected.{ColorInterface.END}')
        print(f'{sudo_output}')
    def kernel_exploit(self):
        old_kernel = ["3.8", "4.4", "4.8", "4.14", "5.0", "5.4"]
        # Check kernel version for known exploits
        print(f'{ColorInterface.OKBLUE}Kernel Exploits: {ColorInterface.END}')
        kernel_ver = subprocess.getoutput("uname -r")
        print(f"Kernel version: {kernel_ver}")
        if kernel_ver.startswith("3.8") or kernel_ver.startswith("4.4") or kernel_ver.startswith("4.8") or kernel_ver.startswith("5.0") or kernel_ver.startswith("5.4"):
         print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Your kernel version ({kernel_ver}) may be vulnerable to known exploits. Consider upgrading.{ColorInterface.END}")

        else:
         print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] Kernel version appears safe based on current knowledge.{ColorInterface.END}")
    def writable_suid_binary(self):
        print(f'{ColorInterface.OKBLUE}Search for Writable SUID/SGID Binary : {ColorInterface.END}')
        suid_binaries = subprocess.getoutput("find / -type f -executable -perm /4000 2>/dev/null")
        if suid_binaries:
         print(f"{BackgroundColorInterface.BACKGROUND_RED}[PARTIAL_VULN] Your system is appear partially vuln because found SUID/SGID{ColorInterface.END}")
         print(suid_binaries)
        else:
           print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] No SUID/SGID binary found {ColorInterface.END}")
    def missing_protections(self):
       print(f'{ColorInterface.OKBLUE}Missing Security Protection: {ColorInterface.END}')
       apparmor = subprocess.getoutput('aa-status')
       if apparmor in '/bin/sh: 1: aa-status: not found' or 'not found' in apparmor:
          print(f'{ColorInterface.BOLD}Apparmor Enabled: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NO{ColorInterface.END}')
       else:
          print(f'{ColorInterface.BOLD}Apparmor Enabled: {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}')
       # Check for ASLR (Address Space Layout Randomization)
       aslr = subprocess.getoutput('cat /proc/sys/kernel/randomize_va_space')
       if aslr == "2":
          print(f'{ColorInterface.BOLD}ASLR Enabled: {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}')
       else:
          print(f'{ColorInterface.BOLD}ASLR Enabled: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NO{ColorInterface.END}')
       # Check for Stack Smashing Protection (SSP)
       ssp = subprocess.getoutput('cat /proc/sys/kernel/exec-shield')
       if ssp == "0":
         print(f'{ColorInterface.BOLD}Stack Smashing Protection (SSP): {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NO{ColorInterface.END}')
       else:
         print(f'{ColorInterface.BOLD}Stack Smashing Protection (SSP): {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}')

         #Check for Grsecurity (if installed)
         grsecurity = subprocess.getoutput('grep -i grsecurity /boot/config-$(uname -r)')
         if "grsecurity" not in grsecurity:
          print(f'{ColorInterface.BOLD}Grsecurity Enabled: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NO{ColorInterface.END}')
         else:
          print(f'{ColorInterface.BOLD}Grsecurity Enabled: {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}')
         # Check for SELinux
         selinux = subprocess.getoutput('sestatus')
         if "command not found" in selinux or 'SELinux status:                 disabled' in selinux:
          print(f'{ColorInterface.BOLD}SELinux Enabled: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NO{ColorInterface.END}')
         else:
          print(f'{ColorInterface.BOLD}SELinux Enabled: {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}')
         # Check if cgroups are enabled
         if os.path.exists("/sys/fs/cgroup"):
            print(f'{ColorInterface.BOLD}Cgroups Enabled: {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}')
         else:
            print(f'{ColorInterface.BOLD}Cgroups Enabled: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NO{ColorInterface.END}')
         # Check if clamav are enabled
         clamav = subprocess.getoutput('clamav --version')
         if "not found" in clamav:
            print(f'{ColorInterface.BOLD}Clamav Enabled: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NO{ColorInterface.END}')
         else:
            print(f'{ColorInterface.BOLD}Clamav Enabled: {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}')
         if os.path.exists('/proc/self/uid_map'):
            print(f'{ColorInterface.BOLD}User Namespaces Enabled: {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}')
         else:
            print(f'{ColorInterface.BOLD}User Namespaces Enabled: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NO{ColorInterface.END}')
         # Check this if is virtual machine
         virt = subprocess.getoutput('systemd-detect-virt')
         if 'none' in virt:
            print(f'{ColorInterface.BOLD}Is this virtual machine: {BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}NO{ColorInterface.END}')
         else:
            print(f'{ColorInterface.BOLD}Is this virtual machine: {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}')
         # Check seccomp is enabled
         seccomp = subprocess.getoutput('cat /proc/self/status | grep Seccomp')
         if seccomp in 'Seccomp:        0':
            print(f'{ColorInterface.BOLD}Seccomp Enabled: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NO{ColorInterface.END}')
         else:
            print(f'{ColorInterface.BOLD}Seccomp Enabled: {BackgroundColorInterface.BACKGROUND_GREEN}YES{ColorInterface.END}') 
         # Check if nftables is active
         nft_output = subprocess.getoutput('nft list ruleset 2>/dev/null')
         if nft_output.strip():
          print(f'{ColorInterface.BOLD}nftables Rules: {BackgroundColorInterface.BACKGROUND_GREEN}ACTIVE{ColorInterface.END}')
         else:
          print(f'{ColorInterface.BOLD}nftables Rules: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NONE{ColorInterface.END}')
         # Check if firewalld is running
         firewalld = subprocess.getoutput('systemctl status firewalld')
         if "active" in firewalld:
          print(f'{ColorInterface.BOLD}Firewalld: {BackgroundColorInterface.BACKGROUND_GREEN}RUNNING{ColorInterface.END}')
         else:
          print(f'{ColorInterface.BOLD}Firewalld: {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}NOT RUNNING{ColorInterface.END}')
    def list_process(self):
       print(f'{ColorInterface.OKBLUE}Process List: {ColorInterface.END}')
       process = subprocess.getoutput('ps -aux')
       print(process)
       print(f'[*] {ColorInterface.OKCYAN}Use pspy for analyze process vulnerability {ColorInterface.END}')
    def check_for_empty_uid(self):
        """
        Checks for users with UID 0 (root) who may not be correctly restricted.
        """
        print(f'{ColorInterface.OKBLUE}Checking for empty UID: {ColorInterface.END}')
        passwd_file = '/etc/passwd'
        with open(passwd_file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                parts = line.split(':')
                uid = int(parts[2])
                if uid == 0:
                    print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] User with UID 0 found: {parts[0]}{ColorInterface.END}')

    def check_for_insecure_shares(self):
        """
        Checks for insecure network shares (e.g., NFS, Samba).
        """
        print(f'{ColorInterface.OKBLUE}Checking for insecure shares: {ColorInterface.END}')
        output = subprocess.getoutput('exportfs -v')
        if "no_root_squash" in output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Insecure NFS export found (no_root_squash).{ColorInterface.END}')
        smb_status = subprocess.getoutput('systemctl status smbd')
        if "active (running)" in smb_status:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] SMB service is running, check for insecure shares.{ColorInterface.END}')
    
    def check_for_unauthorized_usb_devices(self):
        """
        Checks for unauthorized USB devices that could be used for data exfiltration or malware.
        """
        print(f'{ColorInterface.OKBLUE}Checking for unauthorized USB devices: {ColorInterface.END}')
        output = subprocess.getoutput('lsusb')
        if output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[INFO] USB devices detected: {output}{ColorInterface.END}')
        else:
            print(f'{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] No USB devices detected.{ColorInterface.END}')

    def check_for_insecure_x11_sessions(self):
        """
        Checks for insecure X11 sessions that may allow attackers to inject keystrokes.
        """
        print(f'{ColorInterface.OKBLUE}Checking for insecure X11 sessions: {ColorInterface.END}')
        output = subprocess.getoutput('ps aux | grep Xorg')
        if output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] X11 sessions running: {output}{ColorInterface.END}')
        else:
            print(f'{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] No X11 sessions found.{ColorInterface.END}')

    def check_automount_settings(self):
        """
        Checks for automount settings that may expose sensitive data or allow privilege escalation.
        """
        print(f'{ColorInterface.OKBLUE}Checking automount settings: {ColorInterface.END}')
        output = subprocess.getoutput('cat /etc/fstab')
        if 'auto' in output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Automount settings detected in fstab.{ColorInterface.END}')

    def check_for_improper_file_permissions_in_tmp(self):
        """
        Checks for improper file permissions in /tmp that may allow unauthorized access.
        """
        print(f'{ColorInterface.OKBLUE}Checking for improper file permissions in /tmp: {ColorInterface.END}')
        output = subprocess.getoutput('ls -ld /tmp')
        if 'drwxrwxrwt' not in output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Insecure permissions found on /tmp.{ColorInterface.END}')

    def check_for_docker_vulnerabilities(self):
        """
        Scans for Docker vulnerabilities by reviewing running containers and images.
        """
        print(f'{ColorInterface.OKBLUE}Checking for Docker vulnerabilities: {ColorInterface.END}')
        output = subprocess.getoutput('docker ps -a')
        if output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[INFO] Docker containers running: {output}{ColorInterface.END}')
        else:
            print(f'{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] No Docker containers running.{ColorInterface.END}')
    
    def check_for_intrusion_detection(self):
        """
        Checks if intrusion detection systems (e.g., Fail2ban, OSSEC) are enabled.
        """
        print(f'{ColorInterface.OKBLUE}Checking for intrusion detection systems: {ColorInterface.END}')
        fail2ban_status = subprocess.getoutput('systemctl status fail2ban')
        ossec_status = subprocess.getoutput('systemctl status ossec')
        if "active (running)" in fail2ban_status or "active (running)" in ossec_status:
            print(f'{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] Intrusion detection systems are active.{ColorInterface.END}')
        else:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] No intrusion detection systems found.{ColorInterface.END}')

    def check_for_insecure_mounts(self):
        """
        Checks for insecure mount points that might expose sensitive data or allow privilege escalation.
        """
        print(f'{ColorInterface.OKBLUE}Checking for insecure mount points: {ColorInterface.END}')
        output = subprocess.getoutput('mount')
        if 'noexec' not in output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Insecure mounts detected (noexec not set).{ColorInterface.END}')

    def check_for_weak_crypto_settings(self):
        """
        Identifies weak cryptographic settings that could be exploited, such as weak ciphers.
        """
        print(f'{ColorInterface.OKBLUE}Checking for weak cryptographic settings: {ColorInterface.END}')
        ssh_config = subprocess.getoutput('cat /etc/ssh/sshd_config')
        if 'Cipher' in ssh_config:
            weak_ciphers = ['3des', 'blowfish']
            for cipher in weak_ciphers:
                if cipher in ssh_config:
                    print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Weak cipher detected: {cipher}{ColorInterface.END}')

    def check_system_updates(self):
        """
        Checks for outdated system packages that may contain vulnerabilities.
        """
        print(f'{ColorInterface.OKBLUE}Checking system updates: {ColorInterface.END}')
        output = subprocess.getoutput('apt list --upgradable')
        if output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] System updates available: {output}{ColorInterface.END}')
        else:
            print(f'{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] No system updates required.{ColorInterface.END}')

    def check_ssh_config(self):
        """
        Audits the SSH configuration for insecure options, such as PermitRootLogin yes.
        """
        print(f'{ColorInterface.OKBLUE}Checking SSH config: {ColorInterface.END}')
        ssh_config = subprocess.getoutput('cat /etc/ssh/sshd_config')
        if 'PermitRootLogin yes' in ssh_config:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] PermitRootLogin is allowed in SSH config.{ColorInterface.END}')

    def check_empty_passwords(self):
        """
        Checks for users with empty passwords, which is a major security risk.
        """
        print(f'{ColorInterface.OKBLUE}Checking for empty passwords: {ColorInterface.END}')
        with open('/etc/shadow', 'r') as f:
            lines = f.readlines()
            for line in lines:
                fields = line.split(':')
                if fields[1] == '':
                    print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] User with empty password found: {fields[0]}{ColorInterface.END}')

    def check_kernel_modules(self):
        """
        Checks for loaded kernel modules that could be malicious or vulnerable.
        """
        print(f'{ColorInterface.OKBLUE}Checking kernel modules: {ColorInterface.END}')
        output = subprocess.getoutput('lsmod')
        if output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[INFO] Loaded kernel modules: {output}{ColorInterface.END}')
    
    def check_for_race_conditions(self):
        """
        Scans for potential race condition vulnerabilities in system files and processes.
        """
        print(f'{ColorInterface.OKBLUE}Checking for race conditions: {ColorInterface.END}')
        # Simulated check, as race conditions typically require code review
        print(f'{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] No obvious race conditions detected.{ColorInterface.END}')
    
    def check_rhosts_file(self):
        """
        Audits the /etc/hosts.equiv and .rhosts files for insecure configurations.
        """
        print(f'{ColorInterface.OKBLUE}Checking for insecure rhosts file: {ColorInterface.END}')
        if os.path.exists('/etc/hosts.equiv'):
            with open('/etc/hosts.equiv', 'r') as f:
                content = f.read()
                if content:
                    print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Insecure /etc/hosts.equiv file found.{ColorInterface.END}')
    
    def check_nfs_exports(self):
        """
        Checks for NFS exports that are insecure or world-writable.
        """
        print(f'{ColorInterface.OKBLUE}Checking for insecure NFS exports: {ColorInterface.END}')
        output = subprocess.getoutput('exportfs -v')
        if "no_root_squash" in output:
            print(f'{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Insecure NFS export found (no_root_squash).{ColorInterface.END}')
def list_ppid():
    print(f"{ColorInterface.OKBLUE}Process and Parent Process Information:{ColorInterface.END}")

    print(f"{ColorInterface.BOLD}{'PID':<8}{'PPID':<8}{'User':<15}{'Executable / Command':<}{ColorInterface.END}")

    proc_dir = "/proc"
    for pid in os.listdir(proc_dir):
        if not pid.isdigit():
            continue

        try:
            status_path = os.path.join(proc_dir, pid, "status")
            cmdline_path = os.path.join(proc_dir, pid, "cmdline")

            with open(status_path) as f:
                status_info = f.read()

            ppid = re.search(r"^PPid:\s+(\d+)", status_info, re.MULTILINE)
            uid = re.search(r"^Uid:\s+(\d+)", status_info, re.MULTILINE)

            ppid = ppid.group(1) if ppid else "?"
            uid = uid.group(1) if uid else "?"

            try:
                user = subprocess.getoutput(f"getent passwd {uid}").split(":")[0]
            except:
                user = uid

            with open(cmdline_path, "rb") as f:
                cmdline = f.read().replace(b'\x00', b' ').decode(errors="ignore").strip()
                if not cmdline:
                    cmdline = subprocess.getoutput(f"ps -p {pid} -o comm=").strip()

            print(f"{pid:<8}{ppid:<8}{user:<15}{cmdline}")

        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue

def credentials_from_process_memory():
    print(f"{ColorInterface.OKBLUE}Scanning for exposed credentials in user processes (no root required)...{ColorInterface.END}")

    potential_keywords = ["password", "passwd", "PWD", "user", "username", "login", "secret", "token", "auth"]

    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue

        environ_path = f"/proc/{pid}/environ"
        cmdline_path = f"/proc/{pid}/cmdline"
        status_path = f"/proc/{pid}/status"

        try:
            # Ensure we're only inspecting our own processes
            with open(status_path) as f:
                owner_uid = None
                for line in f:
                    if line.startswith("Uid:"):
                        owner_uid = int(line.split()[1])
                        break
                if owner_uid != os.getuid():
                    continue

            # Check command-line args
            with open(cmdline_path, 'rb') as f:
                cmdline = f.read().replace(b'\x00', b' ').decode(errors='ignore')
                for keyword in potential_keywords:
                    if re.search(rf'{keyword}=.+', cmdline, re.IGNORECASE):
                        print(f"\n{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[STRING FOUND IN CMDLINE]{ColorInterface.END}")
                        print(f"PID: {pid}")
                        print(f"Command Line: {cmdline.strip()}")
                        break

            # Check environment variables
            with open(environ_path, 'rb') as f:
                environ = f.read().replace(b'\x00', b'\n').decode(errors='ignore')
                for keyword in potential_keywords:
                    matches = re.findall(rf'{keyword}=.+', environ, re.IGNORECASE)
                    for match in matches:
                        print(f"\n{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[CREDENTIAL FOUND IN ENVIRONMENT]{ColorInterface.END}")
                        print(f"PID: {pid}")
                        print(f"Match: {match.strip()}")

        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue  # Ignore inaccessible processes or those that have exited
            

def cron_list():
    print(f"{ColorInterface.OKBLUE}Enumerating system-wide and user cron jobs:{ColorInterface.END}")

    # System crontab
    print(f"{ColorInterface.BOLD}[*] /etc/crontab:{ColorInterface.END}")
    if os.path.exists("/etc/crontab"):
        print(subprocess.getoutput("cat /etc/crontab"))
    else:
        print("[!] /etc/crontab not found.")

    # /etc/cron.d
    print(f"\n{ColorInterface.BOLD}[*] /etc/cron.d/*:{ColorInterface.END}")
    cron_d_files = subprocess.getoutput("ls /etc/cron.d 2>/dev/null")
    if cron_d_files:
        for f in cron_d_files.splitlines():
            path = os.path.join("/etc/cron.d", f)
            print(f"\n-- {path} --")
            print(subprocess.getoutput(f"cat {path}"))
    else:
        print("[!] No files in /etc/cron.d/")

    # /var/spool/cron
    print(f"\n{ColorInterface.BOLD}[*] /var/spool/cron/* (User Crontabs):{ColorInterface.END}")
    user_crons = subprocess.getoutput("ls /var/spool/cron 2>/dev/null")
    if user_crons:
        for user in user_crons.splitlines():
            path = os.path.join("/var/spool/cron", user)
            print(f"\n-- {path} --")
            print(subprocess.getoutput(f"cat {path}"))
    else:
        print("[!] No user crontabs found.")
def cron_audit():
    print(f"{ColorInterface.OKBLUE}Auditing cron for privilege escalation risks:{ColorInterface.END}")

    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/var/spool/cron/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/"
    ]

    for path in cron_paths:
        if os.path.isfile(path):
            perms = subprocess.getoutput(f"ls -l {path}")
            if "w" in perms.split()[0][2:4]:  # Check group or other writable
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Writable cron file: {path}{ColorInterface.END}")
            elif os.access(path, os.W_OK):
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Current user can write to: {path}{ColorInterface.END}")
        elif os.path.isdir(path):
            for file in os.listdir(path):
                full_path = os.path.join(path, file)
                try:
                    if os.path.isfile(full_path) and os.access(full_path, os.W_OK):
                        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Writable cron script: {full_path}{ColorInterface.END}")
                except:
                    continue

    # Look for suspicious entries
    print(f"\n{ColorInterface.BOLD}Checking for potentially dangerous cron jobs:{ColorInterface.END}")
    suspicious_entries = subprocess.getoutput("grep -rE '(bash|sh|python|nc|perl)' /etc/cron* 2>/dev/null")
    if suspicious_entries:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Suspicious cron commands found:{ColorInterface.END}")
        print(suspicious_entries)
    else:
        print("[-] No obvious dangerous commands in cron jobs.")

def list_timers():
    print(f"{ColorInterface.OKBLUE}Listing active systemd timers:{ColorInterface.END}")

    try:
        timers_output = subprocess.getoutput("systemctl list-timers --all --no-pager")
        if not timers_output.strip():
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] No timers found or systemd not available.{ColorInterface.END}")
            return

        print(timers_output)
    except Exception as e:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed to list timers: {e}{ColorInterface.END}")



def audit_timers():
    print(f"{ColorInterface.OKBLUE}Auditing systemd timers for privilege escalation risks:{ColorInterface.END}")

    # List timer units
    timers = subprocess.getoutput("systemctl list-timers --all --no-pager --no-legend")
    timer_units = [line.split()[0] for line in timers.splitlines() if line.strip().endswith(".timer")]

    if not timer_units:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] No systemd timers detected.{ColorInterface.END}")
        return

    for timer in timer_units:
        try:
            # Get the corresponding service
            service_name = subprocess.getoutput(f"systemctl show {timer} -p Unit").split("=")[-1].strip()
            if not service_name:
                continue

            # Get full path of the service file
            service_file_path = subprocess.getoutput(f"systemctl show -p FragmentPath {service_name}").split("=")[-1].strip()

            if service_file_path and os.path.isfile(service_file_path):
                if os.access(service_file_path, os.W_OK):
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Timer target service is writable: {service_file_path}{ColorInterface.END}")
                elif "tmp" in service_file_path:
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Timer target is in /tmp (potential race condition): {service_file_path}{ColorInterface.END}")

                # Optionally: print suspicious ExecStart
                with open(service_file_path, 'r') as f:
                    content = f.read()
                    if any(bin in content for bin in ["bash", "python", "sh", "nc", "perl"]):
                        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Suspicious ExecStart in {service_file_path}:{ColorInterface.END}")
                        for line in content.splitlines():
                            if "ExecStart" in line:
                                print(f"    {line.strip()}")

        except Exception as e:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed auditing {timer}: {e}{ColorInterface.END}")

def list_service():
    print(f"{ColorInterface.OKBLUE}Listing systemd services (active, inactive, failed):{ColorInterface.END}")

    try:
        # Get the list of services and their status
        service_output = subprocess.getoutput("systemctl list-units --type=service --all --no-pager")

        if not service_output.strip():
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] No services found or systemd not available.{ColorInterface.END}")
            return

        print(service_output)
    except Exception as e:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed to list services: {e}{ColorInterface.END}")

def audit_service():
    print(f"{ColorInterface.OKBLUE}Auditing systemd services for privilege escalation risks:{ColorInterface.END}")

    # List all services, including inactive and failed
    services = subprocess.getoutput("systemctl list-units --type=service --all --no-pager --no-legend")
    service_units = [line.split()[0] for line in services.splitlines() if line.strip().endswith(".service")]

    if not service_units:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] No systemd services detected.{ColorInterface.END}")
        return

    for service in service_units:
        try:
            # Get the corresponding service unit file location
            service_file_path = subprocess.getoutput(f"systemctl show -p FragmentPath {service}").split("=")[-1].strip()

            if service_file_path and os.path.isfile(service_file_path):
                if os.access(service_file_path, os.W_OK):
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Service file is writable: {service_file_path}{ColorInterface.END}")
                elif "tmp" in service_file_path:
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Service file in /tmp or /var/tmp (potential race condition): {service_file_path}{ColorInterface.END}")

                # Check for suspicious ExecStart
                with open(service_file_path, 'r') as f:
                    content = f.read()
                    if any(bin in content for bin in ["bash", "python", "sh", "nc", "perl"]):
                        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Suspicious ExecStart found in {service_file_path}:{ColorInterface.END}")
                        for line in content.splitlines():
                            if "ExecStart" in line:
                                print(f"    {line.strip()}")

                # Check if the service is running as root and is not protected
                unit_status = subprocess.getoutput(f"systemctl show {service} --property=User,Group")
                if "User=root" in unit_status and "Group=root" in unit_status:
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Service running as root: {service}{ColorInterface.END}")
                
        except Exception as e:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed auditing {service}: {e}{ColorInterface.END}")

def audit_socket():
    print(f"{ColorInterface.OKBLUE}Auditing systemd socket units for privilege escalation risks:{ColorInterface.END}")

    # Get all socket units
    sockets_output = subprocess.getoutput("systemctl list-units --type=socket --all --no-pager --no-legend")
    socket_units = [line.split()[0] for line in sockets_output.splitlines() if line.strip().endswith(".socket")]

    if not socket_units:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] No systemd socket units detected.{ColorInterface.END}")
        return

    for socket in socket_units:
        try:
            # Get full path of the socket unit file
            socket_file_path = subprocess.getoutput(f"systemctl show -p FragmentPath {socket}").split("=")[-1].strip()

            # Get the triggered service
            service_trigger = subprocess.getoutput(f"systemctl show {socket} -p Unit").split("=")[-1].strip()

            if socket_file_path and os.path.isfile(socket_file_path):
                if os.access(socket_file_path, os.W_OK):
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Writable socket unit file: {socket_file_path}{ColorInterface.END}")

                # Check content for suspicious commands
                with open(socket_file_path, 'r') as f:
                    content = f.read()
                    if any(cmd in content for cmd in ["bash", "sh", "nc", "python", "perl"]):
                        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Suspicious command found in {socket_file_path}:{ColorInterface.END}")
                        for line in content.splitlines():
                            if "ExecStart" in line or "Exec" in line:
                                print(f"    {line.strip()}")

            # Now audit the associated service
            if service_trigger.endswith(".service"):
                service_path = subprocess.getoutput(f"systemctl show -p FragmentPath {service_trigger}").split("=")[-1].strip()
                if service_path and os.path.isfile(service_path):
                    if os.access(service_path, os.W_OK):
                        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Triggered service is writable: {service_path}{ColorInterface.END}")

                    with open(service_path, 'r') as f:
                        service_content = f.read()
                        if any(cmd in service_content for cmd in ["bash", "sh", "nc", "python", "perl"]):
                            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Suspicious command in triggered service: {service_trigger}{ColorInterface.END}")
                            for line in service_content.splitlines():
                                if "ExecStart" in line:
                                    print(f"    {line.strip()}")

                # Check if it runs as root
                service_user = subprocess.getoutput(f"systemctl show {service_trigger} -p User").split("=")[-1].strip()
                if not service_user or service_user == "root":
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Service triggered by socket runs as root: {service_trigger}{ColorInterface.END}")

        except Exception as e:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed auditing {socket}: {e}{ColorInterface.END}")

def dbus_audit():
    print(f"{ColorInterface.OKBLUE}Auditing D-Bus system services for privilege escalation risks:{ColorInterface.END}")

    # Check if D-Bus is running
    dbus_status = subprocess.getoutput("systemctl is-active dbus")
    if "inactive" in dbus_status or "failed" in dbus_status:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] D-Bus is not active on this system.{ColorInterface.END}")
        return

    # List all system D-Bus services
    dbus_services_dir = "/usr/share/dbus-1/system-services"
    dbus_services = []
    if os.path.isdir(dbus_services_dir):
        dbus_services = [f for f in os.listdir(dbus_services_dir) if f.endswith(".service")]
    else:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] D-Bus system services directory not found.{ColorInterface.END}")
        return

    for service_file in dbus_services:
        full_path = os.path.join(dbus_services_dir, service_file)
        try:
            with open(full_path, "r") as f:
                content = f.read()

            # Check for writable D-Bus service files
            if os.access(full_path, os.W_OK):
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Writable D-Bus service file: {full_path}{ColorInterface.END}")

            # Check if service activates a root binary or dangerous command
            if any(term in content for term in ["bash", "sh", "nc", "python", "perl", "Exec="]):
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Suspicious content in D-Bus service: {full_path}{ColorInterface.END}")
                for line in content.splitlines():
                    if "Exec=" in line or "Service=" in line:
                        print(f"    {line.strip()}")

        except Exception as e:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed to read {full_path}: {e}{ColorInterface.END}")

    # Check for user services (less common but still relevant)
    user_dbus_dir = os.path.expanduser("~/.local/share/dbus-1/services")
    if os.path.isdir(user_dbus_dir):
        user_services = os.listdir(user_dbus_dir)
        for user_service in user_services:
            full_path = os.path.join(user_dbus_dir, user_service)
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] User D-Bus service found: {full_path}{ColorInterface.END}")
            if os.access(full_path, os.W_OK):
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] User-owned service is writable: {full_path}{ColorInterface.END}")

    
def sudo_token_audit():
    print(f"{ColorInterface.OKBLUE}Auditing sudo token session and sudo rules:{ColorInterface.END}")

    # Check if a valid sudo token exists (without password prompt)
    try:
        test = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if test.returncode == 0:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Sudo token is active: current user can run sudo without a password prompt!{ColorInterface.END}")
        else:
            print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] No active sudo token detected (password will be required).{ColorInterface.END}")
    except Exception as e:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed to test sudo token: {e}{ColorInterface.END}")
        return

    # Optional: Show current sudo timestamp if it exists
    timestamp_check = subprocess.getoutput("sudo -nv 2>&1")
    if "timestamp" in timestamp_check or "may not run" not in timestamp_check:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Sudo timestamp status: {timestamp_check.strip()}{ColorInterface.END}")
def pkexec_policy_audit():
    print(f"{ColorInterface.OKBLUE}Auditing pkexec and PolicyKit configuration for privilege escalation risks:{ColorInterface.END}")

    # Step 1: Check if pkexec is available
    pkexec_path = subprocess.getoutput("which pkexec")
    if not pkexec_path or "no pkexec" in pkexec_path:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] pkexec not found on system.{ColorInterface.END}")
        return
    else:
        print(f"{ColorInterface.BOLD}pkexec found at: {pkexec_path}{ColorInterface.END}")

    # Step 2: Try to check if pkexec allows command without password (requires policy file)
    try:
        # Attempt to run a harmless command silently
        test = subprocess.run(["pkexec", "--disable-internal-agent", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if test.returncode == 0:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] pkexec allowed execution without password! Misconfigured PolicyKit rules may allow root command execution.{ColorInterface.END}")
        else:
            print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] pkexec requires authentication (normal behavior).{ColorInterface.END}")
    except Exception as e:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] pkexec execution blocked or user not authorized: {e}{ColorInterface.END}")

    # Step 3: Audit PolicyKit rules and policy files
    polkit_dirs = [
        "/usr/share/polkit-1/actions",      # .policy XML files
        "/etc/polkit-1/rules.d",            # Admin-defined JavaScript rules
        "/usr/share/polkit-1/rules.d"       # Package-defined JavaScript rules
    ]

    for directory in polkit_dirs:
        if os.path.isdir(directory):
            for file in os.listdir(directory):
                full_path = os.path.join(directory, file)

                # Check if the file is writable (can be replaced or modified)
                if os.access(full_path, os.W_OK):
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Writable PolicyKit file: {full_path}{ColorInterface.END}")

                # Check for dangerous rules (e.g., 'yes' or 'auth_admin_keep' replaced with 'yes')
                try:
                    with open(full_path, 'r', errors='ignore') as f:
                        content = f.read()

                        if "yes" in content and ("org.freedesktop.policykit.exec" in content or ".mount" in content):
                            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] PolicyKit rule may allow automatic elevation: {full_path}{ColorInterface.END}")
                            for line in content.splitlines():
                                if "yes" in line or "ALL" in line:
                                    print(f"    {line.strip()}")
                except Exception as e:
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Could not read {full_path}: {e}{ColorInterface.END}")


def critical_file_audit():
    print(f"{ColorInterface.OKBLUE}Auditing critical system files for insecure permissions:{ColorInterface.END}")

    # List of critical files and directories to check
    critical_targets = {
        "/etc/passwd": "User account definitions",
        "/etc/shadow": "User passwords (should be root-only)",
        "/etc/sudoers": "Sudo configuration file",
        "/etc/sudoers.d/": "Additional sudo config",
        "/etc/polkit-1/rules.d/": "PolicyKit rules (potential escalation)",
        "/etc/systemd/system/": "Systemd services (auto-root exec)",
        "/etc/profile": "Global shell config",
        "/etc/bash.bashrc": "Global Bash config",
        "/etc/cron.d/": "Cron jobs",
        "/etc/cron.daily/": "Daily cron tasks",
        "/etc/init.d/": "Init scripts",
        "/etc/rc.local": "Legacy startup script",
        "/root/.bashrc": "Root shell config",
        "/root/.profile": "Root profile config"
    }

    for path, desc in critical_targets.items():
        if os.path.exists(path):
            # Check if file or dir is writable by the current user
            if os.access(path, os.W_OK):
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Writable: {path} — {desc}{ColorInterface.END}")
            else:
                print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] {path} — {desc}{ColorInterface.END}")
        else:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Not found: {path}{ColorInterface.END}")

    # Check for world-writable files in /etc
    print(f"{ColorInterface.BOLD}Scanning for world-writable files in /etc...{ColorInterface.END}")
    try:
        world_writable = subprocess.getoutput("find /etc -xdev -type f -perm -0002 2>/dev/null")
        if world_writable.strip():
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] World-writable files found in /etc:{ColorInterface.END}")
            print(world_writable)
        else:
            print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] No world-writable files found in /etc.{ColorInterface.END}")
    except Exception as e:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Could not scan /etc: {e}{ColorInterface.END}")
def audit_acls():
    print(f"{ColorInterface.OKBLUE}Auditing ACLs (Access Control Lists) on critical system paths:{ColorInterface.END}")

    # Directories to audit for extended ACLs
    target_paths = [
        "/etc",
        "/var",
        "/usr",
        "/root",
        "/home",
        "/tmp",
        "/opt",
        "/srv"
    ]

    for path in target_paths:
        if not os.path.exists(path):
            continue
        try:
            # Use getfacl to retrieve ACLs
            acl_output = subprocess.getoutput(f"getfacl -p {path} 2>/dev/null")

            # Look for non-default ACL entries (e.g., user:<name>:rwx)
            extended_lines = [line for line in acl_output.splitlines() if line.startswith("user:") or line.startswith("group:")]

            if extended_lines:
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Extended ACLs found on: {path}{ColorInterface.END}")
                for line in extended_lines:
                    if not line.startswith("user::") and not line.startswith("group::"):
                        print(f"    {line}")
                        # Highlight potentially dangerous ACLs
                        if "rwx" in line or "x" in line:
                            print(f"    {BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Privilege ACL detected: {line}{ColorInterface.END}")
            else:
                print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] No extended ACLs on: {path}{ColorInterface.END}")
        except Exception as e:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Could not read ACLs for {path}: {e}{ColorInterface.END}")


def list_cap():
    print(f"{ColorInterface.OKBLUE}Listing files with Linux capabilities set:{ColorInterface.END}")
    try:
        cap_list = subprocess.getoutput("getcap -r / 2>/dev/null")
        if cap_list.strip():
            for line in cap_list.splitlines():
                print(f"{ColorInterface.BOLD}{line}{ColorInterface.END}")
        else:
            print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] No files with capabilities found.{ColorInterface.END}")
    except Exception as e:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Could not list capabilities: {e}{ColorInterface.END}")
def audit_cap():
    print(f"{ColorInterface.OKBLUE}Auditing capability assignments for dangerous or uncommon permissions:{ColorInterface.END}")
    try:
        cap_list = subprocess.getoutput("getcap -r / 2>/dev/null")
        if not cap_list.strip():
            print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] No files with extended capabilities found.{ColorInterface.END}")
            return

        for line in cap_list.splitlines():
            try:
                file_path, caps = line.strip().split(' ', 1)
                caps = caps.replace("=", "")

                # Dangerous capabilities to flag
                dangerous = [
                    "cap_setuid", "cap_setgid", "cap_dac_override",
                    "cap_sys_admin", "cap_sys_ptrace", "cap_net_raw",
                    "cap_net_admin", "cap_sys_chroot"
                ]

                if any(d in caps for d in dangerous):
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] {file_path} has dangerous capabilities: {caps}{ColorInterface.END}")
                else:
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] {file_path} has capabilities: {caps}{ColorInterface.END}")

            except ValueError:
                continue  # Skip malformed lines

    except Exception as e:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Could not audit capabilities: {e}{ColorInterface.END}")
def ld_so_audit():
    print(f"{ColorInterface.OKBLUE}Auditing dynamic linker (ld.so) environment and configuration:{ColorInterface.END}")

    # Step 1: Check dangerous environment variables
    ld_env_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"]
    for var in ld_env_vars:
        value = os.environ.get(var)
        if value:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] {var} is set: {value} — This can allow arbitrary code injection.{ColorInterface.END}")
        else:
            print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] {var} is not set.{ColorInterface.END}")

    # Step 2: Check for dangerous or writable library paths in /etc/ld.so.conf and included files
    conf_files = ["/etc/ld.so.conf"]
    conf_dir = "/etc/ld.so.conf.d"

    if os.path.isdir(conf_dir):
        conf_files += [os.path.join(conf_dir, f) for f in os.listdir(conf_dir) if f.endswith(".conf")]

    dangerous_paths = []

    for file in conf_files:
        if not os.path.exists(file):
            continue
        try:
            with open(file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and os.path.isdir(line):
                        if os.access(line, os.W_OK):
                            dangerous_paths.append(line)
                            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Writable library path in ld.so config: {line}{ColorInterface.END}")
                        else:
                            print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] Library path: {line}{ColorInterface.END}")
        except Exception as e:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed reading {file}: {e}{ColorInterface.END}")

    # Step 3: Check for writable .so files in trusted paths
    print(f"{ColorInterface.BOLD}Scanning common library paths for writable .so files...{ColorInterface.END}")
    lib_dirs = ["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib"]

    for path in lib_dirs + dangerous_paths:
        if os.path.isdir(path):
            try:
                result = subprocess.getoutput(f"find {path} -name '*.so*' -writable 2>/dev/null")
                if result.strip():
                    print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Writable .so files in {path}:{ColorInterface.END}")
                    print(result)
            except Exception as e:
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Could not scan {path}: {e}{ColorInterface.END}")

    print(f"{ColorInterface.OKBLUE}Dynamic linker audit complete.{ColorInterface.END}")

def audit_profile():
    print(f"{ColorInterface.OKBLUE}Auditing global shell profile files in /etc for misconfigurations or persistence risks:{ColorInterface.END}")

    # Focused list of global shell config files in /etc
    profile_files = [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zshrc",
        "/etc/zshrc",
    ]

    # Reasonable suspicious terms (avoiding false positives)
    suspicious_keywords = [
        "bash -i", "/dev/tcp", "nc ", "netcat", "ncat", "mkfifo", "curl ", "wget ",
        "python ", "perl ", "exec ", "eval ", "base64", "openssl", "socat"
    ]

    for file in profile_files:
        if os.path.exists(file):
            # Check if file is writable (by current user)
            if os.access(file, os.W_OK):
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Writable global shell config: {file}{ColorInterface.END}")
            else:
                print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] {file} is not user-writable.{ColorInterface.END}")

            # Scan contents for suspicious shell commands
            try:
                with open(file, "r", errors="ignore") as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines, start=1):
                        if line.strip().startswith("#"):
                            continue  # Skip comments
                        for keyword in suspicious_keywords:
                            if keyword in line:
                                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[VULN] Suspicious command in {file} (line {i}): {line.strip()}{ColorInterface.END}")
            except Exception as e:
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed reading {file}: {e}{ColorInterface.END}")
        else:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] File not found: {file}{ColorInterface.END}")

    
def dump_backup():
    print(f"{ColorInterface.OKBLUE}Searching for and dumping backup files for further analysis:{ColorInterface.END}")

    # Common directories where backups are found
    backup_dirs = [
        "/etc/backup",  # Common backup directory for system configs
        "/var/backups",  # Backup directory for system-related backups
        "/root/backup",  # Backup directory in root's home folder
        "/home/*/.backup",  # User backup directories (wildcard for all home dirs)
        "/tmp",  # Temporary backup files (some programs create backups here)
    ]

    # List of common backup file extensions
    backup_extensions = [
        ".tar", ".tar.gz", ".tar.bz2", ".zip", ".bak", ".backup", ".swp", ".sql", ".tgz", ".bak1"
    ]

    # Search for backup files
    found_backups = []

    for directory in backup_dirs:
        # Expand home directories (e.g., "/home/*/.backup")
        if '*' in directory:
            directory = os.path.expanduser(directory)
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in backup_extensions):
                        backup_file = os.path.join(root, file)
                        found_backups.append(backup_file)

    if found_backups:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Found {len(found_backups)} backup files:{ColorInterface.END}")
        for backup in found_backups:
            print(f"{ColorInterface.BOLD}{backup}{ColorInterface.END}")
            # Optionally, copy or move files to a secure directory for further analysis
            # Example: copy backup files to a specified directory for secure review
            # Backup directory for analysis
            analysis_dir = "/tmp/backup_analysis/"
            if not os.path.exists(analysis_dir):
                os.makedirs(analysis_dir)
            try:
                shutil.copy(backup, analysis_dir)
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_GREEN}[INFO] Copied {backup} to {analysis_dir}{ColorInterface.END}")
            except Exception as e:
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed to copy {backup}: {e}{ColorInterface.END}")
    else:
        print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] No backup files found.{ColorInterface.END}")

    
def dump_history():
    print(f"{ColorInterface.OKBLUE}Searching for and dumping shell history files for analysis:{ColorInterface.END}")

    # Common shell history files
    history_files = [
        "/root/.bash_history",  # Root user bash history
        "/root/.zsh_history",   # Root user zsh history
        "/home/*/.bash_history",  # User bash history files (wildcard for all home dirs)
        "/home/*/.zsh_history",   # User zsh history files (wildcard for all home dirs)
        "/home/*/.history",       # Generic history file for shells
    ]

    # List to collect found history files
    found_history = []

    # Search for history files
    for history_file in history_files:
        # Expand user directories like /home/*/.bash_history
        if '*' in history_file:
            history_file = os.path.expanduser(history_file)
        
        if os.path.exists(history_file):
            found_history.append(history_file)

    if found_history:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_YELLOW}[INFO] Found {len(found_history)} history files:{ColorInterface.END}")
        for history in found_history:
            print(f"{ColorInterface.BOLD}{history}{ColorInterface.END}")
            # Optionally, copy or move files to a secure directory for further analysis
            # Example: copy history files to a specified directory for secure review
            analysis_dir = "/tmp/history_analysis/"
            if not os.path.exists(analysis_dir):
                os.makedirs(analysis_dir)
            try:
                shutil.copy(history, analysis_dir)
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_GREEN}[INFO] Copied {history} to {analysis_dir}{ColorInterface.END}")
            except Exception as e:
                print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed to copy {history}: {e}{ColorInterface.END}")
    else:
        print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[SECURE] No history files found.{ColorInterface.END}")

def check_system_logs():
    print(f"{ColorInterface.OKBLUE}Checking system logs for suspicious activity:{ColorInterface.END}")
    log_files = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"]
    suspicious_patterns = ["sudo", "failed", "error", "denied", "root", "bash -i", "nc"]
    for log_file in log_files:
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if any(pattern in line for pattern in suspicious_patterns):
                        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[SUSPICIOUS] {log_file}: {line.strip()}{ColorInterface.END}")

def check_network_ports():
    print(f"{ColorInterface.OKBLUE}Checking open network ports and services:{ColorInterface.END}")
    try:
        netstat_output = subprocess.getoutput('ss -tuln')
        if netstat_output:
            print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_GREEN}[INFO] Open network ports found:{ColorInterface.END}")
            print(netstat_output)
        else:
            print(f"{BackgroundColorInterface.BACKGROUND_GREEN}[INFO] No open network ports found.{ColorInterface.END}")
    except Exception as e:
        print(f"{BackgroundColorInterface.BACKGROUND_BRIGHT_RED}[ERROR] Failed to check network ports: {e}{ColorInterface.END}")


A = AuditScript()
A.basic_info()
A.system_info()
A.sudo_version()
A.sudo_config()
A.kernel_exploit()
A.writable_suid_binary()
A.missing_protections()
A.list_process()
list_ppid()
credentials_from_process_memory()
cron_list()
cron_audit()
list_timers()
audit_timers()
list_service()
audit_service()
audit_socket()
dbus_audit()
sudo_token_audit()
critical_file_audit()
audit_acls()
list_cap()
audit_cap()
ld_so_audit()
audit_profile()
dump_backup()
dump_history()
check_system_logs()
check_network_ports()
A.check_automount_settings()
A.check_for_empty_uid()
A.check_for_insecure_shares()
A.check_for_unauthorized_usb_devices()
A.check_for_insecure_x11_sessions()
A.check_for_empty_uid()
A.check_for_docker_vulnerabilities()
A.check_for_intrusion_detection()
A.check_for_insecure_mounts()
A.check_for_weak_crypto_settings()
A.check_system_updates()
A.check_ssh_config()
A.check_kernel_modules()
A.check_for_race_conditions() # Placeholder in feature version
A.check_rhosts_file()
A.check_nfs_exports()
