# Stdlib
import sys
from datetime import datetime
import enum
import json
import pkg_resources

# Dependencies
import asyncio
import click

# Internally defined
from .tlscheck import Scanner
from .terminal import (
    info,
    error,
    warning
)


class ExitCode(enum.Enum):
    Success = 0
    Failure = 1
    InvalidInput = 2


def welcome() -> datetime:
    start = datetime.now()
    click.echo(info(f"Execution started at: {start}"))
    return start


def bye(start: datetime, exit_code: int) -> None:
    end = datetime.now()
    click.echo(info(f"Execution finished at: {end}"))
    click.echo(info(f"Execution time: {end-start}"))
    sys.exit(exit_code)


@click.group()
def cli():
    pass

async def run_scan(scan):
    await scan.run()


@cli.command()
@click.option('-h', '--host',
              default=None,
              is_flag=False,
              help="target host to scan (e.g.: 'google.com')")
@click.option('-p', '--port',
              default=443,
              is_flag=False,
              show_default="443",
              help="port number to scan.")
def tlscheck(host, port):
    start = welcome()
    if host is None:
        print(error("Host is not optional. "
                    "Please type 'mimir tlscheck --help' for additional info"))
        bye(start, ExitCode.InvalidInput.value)
    click.echo(f"Testing TLS settings for '{host}' on port '{port}'")
    scan = Scanner(host, int(port))
    results = asyncio.run(run_scan(scan))
    print(json.dumps(results, indent=4))


@cli.command()
def version():
    version = pkg_resources.get_distribution("mimirpy").version
    click.echo(f"version {version}")


def main():
    click.CommandCollection(sources=[cli])()
