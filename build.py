import os
import sys
import subprocess
import re

FILES_TO_MERGE = [
    "src/01_foundation.py",
    "src/02_i18n.py",
    "src/03_protocols.py",
    "src/04_tgws.py",
    "src/05_native.py",
    "src/06_subscriptions.py",
    "src/07_hooks.py",
    "src/08_ui.py",
    "src/09_modes.py",
    "src/10_webproxy.py",
]

OUTPUT_FILE = "GreenPass.plugin"

def build():
    print("Starting build...")
    output_content = []

    for file_path in FILES_TO_MERGE:
        if not os.path.exists(file_path):
            print(f"Error: {file_path} not found!")
            sys.exit(1)
            
        print(f"Processing {file_path}...")
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        # Strip local imports, adjust author, version, and update URL
        cleaned_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("from src.") or stripped.startswith("import src."):
                # Comment out or skip the local imports so the combined file remains valid
                continue
            
            if stripped.startswith("__author__ ="):
                line = '__author__ = "@mm1vs"\n'
            elif stripped.startswith("__icon__ ="):
                line = '__icon__ = "monek_icons/0"\n'
            elif stripped.startswith("__version__ ="):
                match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', line)
                if match:
                    orig_version = match.group(1)
                    if not orig_version.endswith('f'):
                        line = f'__version__ = "{orig_version}f"\n'
            elif stripped.startswith("GREENPASS_UPDATE_URL ="):
                line = 'GREENPASS_UPDATE_URL = ""\n'
            elif stripped.startswith("GREENPASS_ELYX_UPDATE_URL ="):
                line = 'GREENPASS_ELYX_UPDATE_URL = ""\n'
                        
            cleaned_lines.append(line)
            
        output_content.extend(cleaned_lines)

    # Write output files
    for target in ("GreenPass.plugin", "GreenPass_new.plugin"):
        with open(target, "w", encoding="utf-8") as out:
            out.write("".join(output_content))
        print(f"Successfully generated {target}")

    # Verify syntax
    print("Verifying syntax...")
    for target in ("GreenPass.plugin", "GreenPass_new.plugin"):
        try:
            result = subprocess.run([sys.executable, "-m", "py_compile", target], 
                                    capture_output=True, text=True)
            if result.returncode == 0:
                print(f"Syntax check passed for {target}!")
            else:
                print(f"Syntax check failed for {target}!")
                print(result.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Could not run syntax check for {target}: {e}")

if __name__ == "__main__":
    build()
