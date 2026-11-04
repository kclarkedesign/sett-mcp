from pathlib import Path

import pytest

from sett_mcp import __version__
from sett_mcp.cli import main

REPO = Path(__file__).resolve().parents[1]


def test_new_renders_the_template(tmp_path):
    target = tmp_path / "weather"
    main(["new", str(target), "--defaults", "--template", str(REPO), "--ref", "HEAD", "-d", "project_name=Weather MCP"])
    assert (target / "src/weather_mcp/guardrails.py").exists()
    assert "project_slug: weather-mcp" in (target / ".copier-answers.yml").read_text()


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert __version__ in capsys.readouterr().out


def test_bad_data_pair_is_rejected(tmp_path):
    with pytest.raises(SystemExit, match="KEY=VALUE"):
        main(["new", str(tmp_path / "x"), "-d", "oops"])
