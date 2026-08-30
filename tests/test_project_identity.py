"""Repository-wide identity contract for the Project Umbra rename."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".html",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def test_repository_contains_no_legacy_project_identity() -> None:
    legacy_package = "ghost" + "protocol"
    legacy_slug = "ghost" + "-protocol"
    violations: list[str] = []

    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in {".git", ".venv", "data", "__pycache__"} for part in path.parts):
            continue

        relative = path.relative_to(ROOT)
        searchable = f"{relative}\n{path.read_text(encoding='utf-8', errors='ignore')}".lower()
        if legacy_package in searchable or legacy_slug in searchable:
            violations.append(str(relative))

    assert not violations, "Legacy project identity remains in: " + ", ".join(sorted(violations))


def test_project_umbra_package_and_agent_are_canonical() -> None:
    from project_umbra import ProjectUmbraAgent, settings

    assert ProjectUmbraAgent.__name__ == "ProjectUmbraAgent"
    assert settings.APP_NAME == "Project Umbra"
    assert (ROOT / "project_umbra").is_dir()
    assert 'name = "project-umbra"' in (ROOT / "pyproject.toml").read_text()
