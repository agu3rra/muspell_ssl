import click


def main():
    run()


@click.command()
@click.version_option()
def run():
    click.echo("Hello!")
