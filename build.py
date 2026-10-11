import os
import sys
import subprocess
import re
import zipfile

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

OUTPUT_PLUGIN = "GreenPass.plugin"
OUTPUT_ELYX = "GreenPass.elyx"

def build():
    print("Starting build...")
    output_content = []
    version_str = "2.5.7"

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
                    line = f'__version__ = "{orig_version}"\n'
                    version_str = orig_version
            elif stripped.startswith("GREENPASS_UPDATE_URL ="):
                line = 'GREENPASS_UPDATE_URL = ""\n'
            elif stripped.startswith("GREENPASS_ELYX_UPDATE_URL ="):
                line = 'GREENPASS_ELYX_UPDATE_URL = ""\n'
                        
            cleaned_lines.append(line)
            
        output_content.extend(cleaned_lines)

    compiled_code = "".join(output_content)

    # 1. Write standalone GreenPass.plugin
    with open(OUTPUT_PLUGIN, "w", encoding="utf-8") as out:
        out.write(compiled_code)
    print(f"Successfully generated {OUTPUT_PLUGIN}")

    # 2. Write packaged GreenPass.elyx
    refmap_content = "metainfo: plugin/meta.yml\nmain: plugin/main.py\nelyxbuilder: plugin/.elyxbuilder\n"
    meta_content = (
        'name: GreenPass\n'
        'description: "Практически универсальный прокси-плагин для exteraGram"\n'
        'id: GreenPass\n'
        f'version: "{version_str}"\n'
        'author: "@mm1vs"\n'
        'app_version: ">=12.1.1"\n'
        'icon: monek_icons/0\n'
    )
    elyx_config = "zipFormat: eaf\nsource: plugin\n"

    with zipfile.ZipFile(OUTPUT_ELYX, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("refmap.yml", refmap_content)
        z.writestr("plugin/meta.yml", meta_content)
        z.writestr("plugin/main.py", compiled_code)
        z.writestr("plugin/.elyxbuilder/config.yml", elyx_config)
    print(f"Successfully generated {OUTPUT_ELYX}")

    # 3. Verify syntax
    print("Verifying syntax...")
    try:
        result = subprocess.run([sys.executable, "-m", "py_compile", OUTPUT_PLUGIN], 
                                capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Syntax check passed for {OUTPUT_PLUGIN}!")
        else:
            print(f"Syntax check failed for {OUTPUT_PLUGIN}!")
            print(result.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Could not run syntax check for {OUTPUT_PLUGIN}: {e}")

if __name__ == "__main__":
    build()
