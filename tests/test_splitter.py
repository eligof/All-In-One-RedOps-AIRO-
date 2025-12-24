import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "airo-redops-v3.2.0"


def _ensure_build():
    if BUILD_DIR.exists():
        return
    subprocess.run(["python", "airo-splitter.py"], cwd=ROOT, check=True)


def test_build_outputs_exist():
    _ensure_build()
    assert (BUILD_DIR / "airo-core.sh").is_file()
    assert (BUILD_DIR / "install.sh").is_file()
    assert (BUILD_DIR / "uninstall.sh").is_file()
    assert (BUILD_DIR / "modules").is_dir()
    assert (BUILD_DIR / "config").is_dir()
    assert (BUILD_DIR / "docs").is_dir()
    assert (BUILD_DIR / "vendors" / "tools.json").is_file()


def test_docs_copied():
    _ensure_build()
    assert (BUILD_DIR / "DOCS.md").is_file()
    assert (BUILD_DIR / "docs" / "DOCS.md").is_file()
    assert (BUILD_DIR / "README.md").is_file()
    assert (BUILD_DIR / "docs" / "README.md").is_file()


def test_xdg_config_templates():
    _ensure_build()
    config_dir = BUILD_DIR / "config"
    assert (config_dir / "defaults.conf").is_file()
    assert (config_dir / "config.ini").is_file()
    assert (config_dir / "user.conf.example").is_file()
