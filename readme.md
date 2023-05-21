# Mimir Py
A Python 🐍 TLS connection tester🔒licensed under MIT.

PS: This was an older project of mine that I wished to package as a CLI using [click](https://click.palletsprojects.com/en/8.1.x/).

## Install
```bash
pip install mimirpy
```

PS: if you use [python poetry](https://python-poetry.org/), make sure you install on a `poetry virtualenv` and activate `poetry shell`.

## Usage
```
$ mimir tlscheck --host foobar.com --port 1234
Supported cypher suites for foobar.com on port 1234:

...
```
