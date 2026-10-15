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
    version_str = "2.5.14"

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
                        
            cleaned_lines.append(line)
            
        output_content.extend(cleaned_lines)

    compiled_code = "".join(output_content)

    def source_metadata(name, default=""):
        match = re.search(
            r"^\s*" + re.escape(name) + r"\s*=\s*[\"']([^\"']+)[\"']",
            compiled_code,
            re.MULTILINE,
        )
        return match.group(1).strip() if match else str(default)

    plugin_id = source_metadata("__id__", "GreenPass")
    plugin_name = source_metadata("__name__", "GreenPass")
    plugin_author = source_metadata("__author__", "@mm1vs")
    plugin_app_version = source_metadata("__app_version__", ">=12.5.1")
    plugin_sdk_version = source_metadata("__sdk_version__", ">=1.4.4.3")

    # 1. Write standalone GreenPass.plugin
    with open(OUTPUT_PLUGIN, "w", encoding="utf-8") as out:
        out.write(compiled_code)
    print(f"Successfully generated {OUTPUT_PLUGIN}")

    # 2. Write packaged GreenPass.elyx
    refmap_path = "refmap.yml"
    if os.path.exists(refmap_path):
        with open(refmap_path, "r", encoding="utf-8") as refmap_file:
            refmap_content = refmap_file.read()
    else:
        refmap_content = "metainfo: plugin/meta.yml\nmain: plugin/main.py\nelyxbuilder: plugin/.elyxbuilder\n"
    meta_content = (
        f'name: {plugin_name}\n'
        'description: "Практически универсальный прокси-плагин для exteraGram"\n'
        f'id: {plugin_id}\n'
        f'version: "{version_str}"\n'
        f'author: "{plugin_author}"\n'
        f'app_version: "{plugin_app_version}"\n'
        f'sdk_version: "{plugin_sdk_version}"\n'
        'icon: monek_icons/0\n'
    )
    with zipfile.ZipFile(OUTPUT_ELYX, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("refmap.yml", refmap_content)
        z.writestr("plugin/meta.yml", meta_content)
        z.writestr("plugin/main.py", compiled_code)
        # Elyx resolves payloads relative to plugin/.elyxbuilder/config.yml and refmap.yml.
        # Package all checked-in plugin assets including runtime wheels under plugin/wheels.
        for root, dirs, files in os.walk("plugin"):
            dirs[:] = [name for name in dirs if name != "cache" and not name.startswith("__pycache__")]
            archive_dir = root.replace(os.sep, "/").rstrip("/") + "/"
            z.writestr(archive_dir, "")
            for filename in files:
                source_path = os.path.join(root, filename)
                archive_path = source_path.replace(os.sep, "/")
                if archive_path in ("plugin/main.py", "plugin/meta.yml"):
                    continue
                z.write(source_path, archive_path)
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
