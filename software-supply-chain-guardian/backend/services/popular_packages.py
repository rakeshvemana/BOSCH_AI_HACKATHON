"""Widely used package names, the usual targets of typosquatting.

A dependency whose name is ONE edit away from one of these (or identical once
separators are removed), but is not itself on the list, is flagged for review.
The lists are intentionally hand-curated and small; extend them as needed.
"""
from __future__ import annotations

PYPI = frozenset("""
boto3 botocore urllib3 requests setuptools certifi charset-normalizer idna typing-extensions python-dateutil
packaging s3transfer aiobotocore six numpy pyyaml grpcio grpcio-status s3fs fsspec pip cryptography pydantic
pydantic-core cffi attrs google-api-core pycparser pandas importlib-metadata jmespath protobuf wheel rsa pyasn1
pyasn1-modules zipp click platformdirs pytz jinja2 markupsafe colorama awscli filelock virtualenv tomli tomlkit
toml pluggy pytest pytest-cov pytest-mock pytest-asyncio pytest-xdist googleapis-common-protos wrapt pyjwt
cachetools jsonschema google-auth pyparsing sqlalchemy docutils aiohttp psutil multidict yarl frozenlist
aiosignal iniconfig decorator tqdm scipy scapy pillow lxml requests-oauthlib oauthlib werkzeug flask greenlet
beautifulsoup4 soupsieve openpyxl tzdata isodate msgpack pygments exceptiongroup httpx httpcore anyio sniffio
h11 distlib more-itertools websocket-client websockets coverage matplotlib regex rich markdown markdown-it-py
mdurl scikit-learn joblib threadpoolctl networkx sympy mpmath torch torchvision transformers tokenizers
huggingface-hub safetensors django djangorestframework fastapi starlette uvicorn gunicorn redis celery kombu
psycopg2 psycopg2-binary pymysql mysqlclient paramiko pynacl bcrypt selenium black flake8 mypy isort pylint
ruff pre-commit tox nltk opencv-python tensorflow keras xgboost lightgbm seaborn plotly dash streamlit gradio
openai anthropic langchain colorlog termcolor tabulate simplejson ujson orjson pyopenssl setuptools-scm docker
kubernetes ansible jupyter notebook ipython ipykernel nose mock freezegun faker arrow pendulum babel sphinx
alembic marshmallow sentry-sdk google-cloud-storage azure-core azure-storage-blob pyarrow polars dask numba
llvmlite cython pybind11 jupyterlab typer python-dotenv pyserial pywin32 pymongo elasticsearch boto
""".split())

NPM = frozenset("""
lodash react react-dom express chalk commander debug axios tslib moment request uuid async glob minimist semver
yargs yargs-parser fs-extra bluebird underscore webpack typescript jquery vue angular rxjs inquirer colors color
color-name color-convert body-parser mkdirp rimraf dotenv classnames prop-types core-js @babel/core babel-core
eslint prettier jest mocha chai sinon cross-env nodemon socket.io socket.io-client mongoose redis mysql mysql2
sequelize knex jsonwebtoken bcrypt bcryptjs cors morgan helmet passport cheerio puppeteer node-fetch
cookie-parser cookie cookies dayjs date-fns immutable redux react-redux react-router react-router-dom
styled-components graphql apollo-server next nuxt vite rollup esbuild gulp grunt karma jasmine handlebars pug
ejs marked highlight.js superagent request-promise through2 readable-stream iconv-lite safe-buffer inherits
source-map ansi-styles supports-color has-flag escape-string-regexp strip-ansi string-width wrap-ansi cliui
camelcase lru-cache minimatch brace-expansion picomatch micromatch chokidar node-gyp electron three chart.js
winston bunyan nanoid shelljs execa cross-spawn http-proxy express-session multer form-data mime mime-types
event-stream coffee-script ajv typeorm prisma @prisma/client vitest playwright webpack-cli babel-loader
css-loader style-loader sass postcss autoprefixer tailwindcss
""".split())

# Legitimate, widely used packages whose names happen to sit one edit from a popular one.
KNOWN_LEGITIMATE = {
    "npm": frozenset("safer-buffer exec inherit colour picocolors".split()),
    "pypi": frozenset("pyaml attr jinja colour".split()),
}

POPULAR = {"pypi": PYPI, "npm": NPM}


def within_one_edit(a: str, b: str) -> bool:
    """True if a and b differ by exactly one insertion, deletion, substitution or adjacent swap. O(len)."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    i = 0
    while i < min(la, lb) and a[i] == b[i]:
        i += 1
    if la == lb:
        if a[i + 1:] == b[i + 1:]:
            return True  # substitution
        return i + 1 < la and a[i] == b[i + 1] and a[i + 1] == b[i] and a[i + 2:] == b[i + 2:]  # transposition
    if la > lb:
        return a[i + 1:] == b[i:]  # deletion from a
    return a[i:] == b[i + 1:]      # insertion into a


def _squash(name: str) -> str:
    return name.replace("-", "").replace("_", "").replace(".", "")


def lookalike_of(name: str, ecosystem: str) -> tuple[str, str] | None:
    """(popular package it resembles, how) or None."""
    popular = POPULAR.get(ecosystem)
    if not popular or name in popular or name in KNOWN_LEGITIMATE.get(ecosystem, ()):
        return None
    bare = name.split("/", 1)[-1] if name.startswith("@") else name
    sq = _squash(name)
    for p in popular:
        if len(p) < 5:
            continue
        if _squash(p) == sq:
            return p, "same name with different separators"
        if within_one_edit(name, p) or (bare != name and within_one_edit(bare, p)):
            return p, "one character away"
    return None
