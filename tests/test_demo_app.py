"""Smoke test: the demo app's quick pages render and their main buttons work."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP_DIR = Path(__file__).resolve().parent.parent / "app"


def page(name: str) -> AppTest:
    code = f"import sys; sys.path.insert(0, {str(APP_DIR)!r}); import demo_app; demo_app.{name}()"
    at = AppTest.from_string(code, default_timeout=120)
    at.run()
    assert not at.exception
    return at


def click(at: AppTest, label_start: str) -> None:
    next(b for b in at.button if b.label.startswith(label_start)).click().run()
    assert not at.exception


@pytest.mark.parametrize("name", ["page_overview", "page_act1", "page_act2", "page_act4", "page_epilogue"])
def test_page_renders(name):
    page(name)


def test_act3_send_attack_receive():
    at = page("page_act3")
    click(at, "Send from Alice")
    click(at, "Forge as Alice")
    click(at, "Bob verifies")
    results = at.dataframe[-1].value["result"].tolist()
    assert results == ["✅ accepted", "❌ rejected"]


def test_act5_only_the_approved_model_loads():
    at = page("page_act5")
    click(at, "Run the five attempts")
    assert len(at.success) == 1 and len(at.error) == 4
