#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Mobile Security Tools for Pegasus-Suite
"""

import os
import sys
import re
import subprocess
import platform
import random
import time

class MobileSecurityTools:
    """Mobile application security analysis tools"""
    
    def __init__(self):
        """Initialize mobile security tools"""
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        self.output_dir = "mobile_analysis_results"
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except:
                self.output_dir = "."
    
    @staticmethod
    def inspect_mobile_archive(path, extension):
        """Report only facts verified from ZIP metadata; never invent findings."""
        import hashlib
        import zipfile

        if not os.path.isfile(path) or not path.lower().endswith(extension):
            raise ValueError("File is missing or has the wrong extension")
        if not zipfile.is_zipfile(path):
            raise ValueError("Invalid ZIP archive")
        size = os.path.getsize(path)
        if size > 1024 * 1024 * 1024:
            raise ValueError("Archive larger than 1 GiB is not supported")
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 50000:
                raise ValueError("Too many archive entries")
            if sum(info.file_size for info in entries) > 2 * 1024 ** 3:
                raise ValueError("Expanded archive size exceeds 2 GiB")
            if archive.testzip() is not None:
                raise ValueError("Corrupt archive entry")
            filenames = [item.filename for item in entries]
            if extension == ".apk":
                manifest_found = "AndroidManifest.xml" in filenames
            else:
                manifest_found = any(
                    name.startswith("Payload/") and name.endswith(".app/Info.plist")
                    for name in filenames
                )
            if not manifest_found:
                raise ValueError("Expected application manifest not found")
        return {
            "file": os.path.basename(path),
            "size_bytes": size,
            "sha256": digest.hexdigest(),
            "entries": len(entries),
            "manifest_present": manifest_found,
        }

    def _archive_analyzer(self, extension):
        label = "Android APK" if extension == ".apk" else "iOS IPA"
        path = input("Enter path to {} file: ".format(label)).strip()
        try:
            facts = self.inspect_mobile_archive(path, extension)
        except (ValueError, OSError, __import__("zipfile").BadZipFile) as exc:
            print("[!] Analysis failed: {}".format(exc))
            input("\nPress Enter to continue...")
            return

        report = (
            "{} archive inspection (not a vulnerability assessment)\n"
            "File: {}\nSize (bytes): {}\nSHA-256: {}\n"
            "Archive entries: {}\nExpected manifest present: {}\n"
            "Permissions: NOT ANALYZED\nSecurity vulnerabilities: NOT ANALYZED\n"
            "No security conclusions can be drawn from archive structure alone.\n"
        ).format(label, facts["file"], facts["size_bytes"], facts["sha256"],
                 facts["entries"], facts["manifest_present"])
        print(report)
        report_path = os.path.join(
            self.output_dir, "{}_archive_{}.txt".format(
                extension.lstrip("."), facts["sha256"][:16]
            )
        )
        try:
            with open(report_path, "w", encoding="utf-8") as handle:
                handle.write(report)
            print("[+] Report saved: {}".format(report_path))
        except OSError as exc:
            print("[!] Cannot save report: {}".format(exc))
        input("\nPress Enter to continue...")

    def android_app_analyzer(self):
        """Inspect APK container facts without claiming a security scan."""
        self._archive_analyzer(".apk")

    def ios_app_analyzer(self):
        """Inspect IPA container facts without claiming a security scan."""
        self._archive_analyzer(".ipa")

    def mobile_vulnerability_scanner(self):
        """Scan for mobile device vulnerabilities"""
        print("[+] Mobile Vulnerability Scanner")
        
        device_type = input("Select device type (1: Android, 2: iOS): ")
        
        if device_type not in ["1", "2"]:
            print("[!] Invalid selection.")
            input("\nPress Enter to continue...")
            return
            
        device_id = input("Enter device ID/IP (or leave empty for simulation): ")
        
        # Simulate vulnerability scan
        print("\n[*] This is a simulated scan. In a real environment, you would connect to the device.")
        
        if device_type == "1":  # Android
            print("[*] Scanning Android device for vulnerabilities...")
            
            # Common Android vulnerabilities
            vulnerabilities = [
                ("Outdated OS", "Device running Android version < 10", random.random() < 0.4),
                ("Missing Security Patches", "Device missing recent security updates", random.random() < 0.5),
                ("USB Debugging Enabled", "USB debugging is enabled in developer options", random.random() < 0.3),
                ("Potentially Harmful Apps", "Device has apps from unknown sources", random.random() < 0.4),
                ("Root Access", "Device is rooted", random.random() < 0.2),
                ("Encryption Disabled", "Device storage is not encrypted", random.random() < 0.3),
                ("Vulnerable Bootloader", "Bootloader could allow unauthorized OS installation", random.random() < 0.2)
            ]
        else:  # iOS
            print("[*] Scanning iOS device for vulnerabilities...")
            
            # Common iOS vulnerabilities
            vulnerabilities = [
                ("Outdated OS", "Device running iOS version < 14", random.random() < 0.3),
                ("Jailbroken Device", "Device shows signs of jailbreak", random.random() < 0.2),
                ("Profile Management", "Device has suspicious profiles installed", random.random() < 0.3),
                ("MDM Bypass", "Mobile Device Management appears to be bypassed", random.random() < 0.1),
                ("Vulnerable Safari Settings", "Browser privacy settings are not optimal", random.random() < 0.4),
                ("iCloud Security", "iCloud security settings are not optimal", random.random() < 0.3),
                ("AppStore Restrictions", "App installation restrictions are bypassed", random.random() < 0.2)
            ]
        
        # Simulate scan progress
        for i in range(1, 6):
            print(f"[*] Scan progress: {i*20}%")
            time.sleep(0.5)
        
        # Report findings
        found_vulnerabilities = [(name, desc) for name, desc, found in vulnerabilities if found]
        
        if found_vulnerabilities:
            print("\n[!] Vulnerabilities detected:")
            for name, desc in found_vulnerabilities:
                print(f"  - {name}: {desc}")
        else:
            print("\n[+] No vulnerabilities detected. Device appears secure.")
        
        input("\nPress Enter to continue...")
    
    def app_permission_analyzer(self):
        """Analyze app permissions on a mobile device"""
        print("[+] App Permission Analyzer")
        
        device_type = input("Select device type (1: Android, 2: iOS): ")
        
        if device_type not in ["1", "2"]:
            print("[!] Invalid selection.")
            input("\nPress Enter to continue...")
            return
        
        print("\n[*] This is a simulated analysis. In a real environment, you would connect to the device.")
        
        # Simulate list of installed apps
        apps = []
        if device_type == "1":  # Android
            apps = [
                "com.google.android.gms",
                "com.android.chrome",
                "com.facebook.katana",
                "com.instagram.android",
                "com.whatsapp",
                "com.spotify.music",
                "com.netflix.mediaclient",
                "com.amazon.mShop.android.shopping",
                "com.ubercab",
                "com.snapchat.android"
            ]
        else:  # iOS
            apps = [
                "com.apple.mobilesafari",
                "com.facebook.Facebook",
                "com.instagram.Instagram",
                "com.burbn.instagram",
                "net.whatsapp.WhatsApp",
                "com.spotify.client",
                "com.netflix.Netflix",
                "com.amazon.Amazon",
                "com.ubercab.UberClient",
                "com.toyopagroup.picaboo"
            ]
        
        # Show list of apps
        print("\n[*] Installed apps:")
        for i, app in enumerate(apps, 1):
            print(f"  {i}. {app}")
        
        app_choice = input("\nSelect an app to analyze (number): ")
        try:
            app_choice = int(app_choice)
            if app_choice < 1 or app_choice > len(apps):
                raise ValueError()
            selected_app = apps[app_choice - 1]
        except (ValueError, IndexError):
            print("[!] Invalid selection.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n[*] Analyzing permissions for {selected_app}...")
        
        # Simulate permissions based on app type
        permissions = []
        
        if "facebook" in selected_app.lower() or "instagram" in selected_app.lower() or "snap" in selected_app.lower():
            permissions = [
                ("Camera", "High", "Allows app to take pictures and videos"),
                ("Microphone", "High", "Allows app to record audio"),
                ("Location", "High", "Allows app to access precise location"),
                ("Contacts", "High", "Allows app to read your contacts"),
                ("Storage", "Medium", "Allows app to read and write to storage"),
                ("Phone", "Medium", "Allows app to read phone status"),
                ("SMS", "High", "Allows app to read and send SMS messages"),
            ]
        elif "netflix" in selected_app.lower() or "spotify" in selected_app.lower():
            permissions = [
                ("Storage", "Medium", "Allows app to read and write to storage"),
                ("Network", "Low", "Allows app to access network connections"),
                ("Microphone", "Medium", "Allows app to record audio"),
                ("Wake Lock", "Low", "Allows app to keep processor from sleeping"),
            ]
        elif "chrome" in selected_app.lower() or "safari" in selected_app.lower():
            permissions = [
                ("Location", "Medium", "Allows app to access precise location"),
                ("Camera", "Medium", "Allows app to take pictures"),
                ("Storage", "Medium", "Allows app to read and write to storage"),
                ("Microphone", "Medium", "Allows app to record audio"),
            ]
        else:
            # Generic permissions
            permissions = [
                ("Internet", "Low", "Allows app to access the internet"),
                ("Storage", "Medium", "Allows app to read and write to storage"),
                ("Location", "Medium", "Allows app to access location"),
            ]
        
        # Randomly select some permissions
        selected_permissions = random.sample(permissions, min(len(permissions), random.randint(3, len(permissions))))
        
        print("\n[+] Permissions detected:")
        for perm, risk, desc in selected_permissions:
            print(f"  - {perm} ({risk} risk): {desc}")
        
        # Risk assessment
        high_risk = sum(1 for perm, risk, _ in selected_permissions if risk == "High")
        medium_risk = sum(1 for perm, risk, _ in selected_permissions if risk == "Medium")
        
        print("\n[+] Risk assessment:")
        if high_risk >= 3:
            print("  High Risk: App requests many sensitive permissions")
        elif high_risk >= 1 or medium_risk >= 3:
            print("  Medium Risk: App requests some sensitive permissions")
        else:
            print("  Low Risk: App requests minimal sensitive permissions")
        
        print("\n[*] Recommendations:")
        if high_risk > 0:
            print("  - Review if the app really needs these permissions")
            print("  - Consider using alternative apps with fewer permissions")
            print("  - Disable permissions that aren't necessary for app functionality")
        
        input("\nPress Enter to continue...")

def run_mobile_security_tools():
    """Run the mobile security tools"""
    return MobileSecurityTools()

# Function to display the mobile security menu
def mobile_security_menu():
    """Display the mobile security menu"""
    tools = run_mobile_security_tools()
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    ###########################################
    #          Mobile Security Tools          #
    ###########################################
    
    1. Android App Analyzer
    2. iOS App Analyzer
    3. Mobile Vulnerability Scanner
    4. App Permission Analyzer
    5. Back to Main Menu
    """)
        
        choice = input("Select an option: ")
        
        try:
            choice = int(choice)
            if choice == 1:
                tools.android_app_analyzer()
            elif choice == 2:
                tools.ios_app_analyzer()
            elif choice == 3:
                tools.mobile_vulnerability_scanner()
            elif choice == 4:
                tools.app_permission_analyzer()
            elif choice == 5:
                return
            else:
                print("Invalid option. Please try again.")
                input("\nPress Enter to continue...")
        except ValueError:
            print("Please enter a number.")
            input("\nPress Enter to continue...")

# For standalone testing
if __name__ == "__main__":
    mobile_security_menu() 