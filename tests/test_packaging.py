"""
Yayın öncesi paketleme kontrolleri (release workflow'u da bunları koşar).
"""
import importlib.util
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = {
    "telveguard-core": ROOT / "packages/telveguard-core",
    "telveguard-contextforge": ROOT / "packages/telveguard-contextforge",
}


def pyproject(name):
    return tomllib.loads((PACKAGES[name] / "pyproject.toml").read_text(encoding="utf-8"))["project"]


@pytest.mark.parametrize("name", PACKAGES)
def test_license_copy_matches_root(name):
    """sdist paket dizini dışını içeremez; kopya kökteki LICENSE ile aynı kalmalı."""
    assert (PACKAGES[name] / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes(), \
        f"Güncelleyin: cp LICENSE packages/{name}/LICENSE"


def test_versions_are_consistent():
    core, cf = pyproject("telveguard-core"), pyproject("telveguard-contextforge")
    assert core["version"] == cf["version"], "Paketler birlikte sürümlenir"
    from telveguard_core import __version__
    assert __version__ == core["version"]
    manifest = yaml.safe_load((PACKAGES["telveguard-contextforge"] /
                               "telveguard_contextforge/plugin-manifest.yaml").read_text(encoding="utf-8"))
    assert manifest["version"] == cf["version"]
    # Eklenti, kendi sürümüyle yayınlanan çekirdeğe bağımlı olmalı
    assert f"telveguard-core>={core['version']}" in cf["dependencies"]


@pytest.mark.parametrize("name", PACKAGES)
def test_metadata_ready_for_pypi(name):
    p = pyproject(name)
    assert p["license"] == "Apache-2.0" and p["license-files"] == ["LICENSE"]
    assert p["readme"] == "README.md" and (PACKAGES[name] / "README.md").is_file()
    assert p["urls"]["Source"] == "https://github.com/osmanuygar/telveguard"


@pytest.mark.skipif(importlib.util.find_spec("build") is None, reason="build paketi yok")
@pytest.mark.parametrize("name", PACKAGES)
def test_builds_and_passes_twine_check(name, tmp_path):
    out = subprocess.run([sys.executable, "-m", "build", str(PACKAGES[name]), "-o", str(tmp_path)],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr[-2000:]
    dists = sorted(tmp_path.iterdir())
    assert sorted(d.suffix for d in dists) == [".gz", ".whl"]  # sdist + wheel
    if importlib.util.find_spec("twine"):
        check = subprocess.run([sys.executable, "-m", "twine", "check", "--strict", *map(str, dists)],
                               capture_output=True, text=True)
        assert check.returncode == 0, check.stdout + check.stderr
    # Wheel: lisans dahil, testler / gereksiz dosyalar hariç
    with zipfile.ZipFile(next(d for d in dists if d.suffix == ".whl")) as whl:
        names = whl.namelist()
    module = name.replace("-", "_")
    assert any(n.endswith("/licenses/LICENSE") for n in names)
    assert all(n.startswith((f"{module}/", f"{module}-")) for n in names), names
