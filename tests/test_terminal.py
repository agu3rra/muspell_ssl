import os
import pytest
from click.testing import CliRunner, Result
import mimirpy as cli


@pytest.fixture(autouse=False)
def runner() -> CliRunner:
    return CliRunner()


def assert_result(result: Result, exit_code: int, output_contains: str) -> None:
    assert result.exit_code == exit_code
    assert result.output.find(output_contains) >= 0


def test_help(runner):
    result = runner.invoke(cli.run, ["--help"])
    assert_result(result, 0, "Usage")


def test_version(runner):
    result = runner.invoke(cli.run, ["--version"])
    assert_result(result, 0, "version")