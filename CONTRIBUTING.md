# Contributing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest ruff
```

## Running tests

```bash
pytest tests/ -v
```

## Linting

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Adding new IoCs

Add known indicators to `src/glassworm_hunter/engine/ioc.py` (hardcoded layer) and `data/ioc.json` (bundled layer). Both layers are merged at runtime - duplicates are handled automatically.

## Adding detection rules

1. Add pattern to the appropriate file in `src/glassworm_hunter/engine/` (unicode.py, behavioral.py, or ioc.py)
2. Add a `DetectionType` enum value in `models.py`
3. Write tests covering both true positives and false positives
4. Run `ruff check` and `ruff format` before submitting

## Submitting changes

1. Fork the repository
2. Create a branch from `main`
3. Make your changes
4. Ensure `pytest` and `ruff check` pass
5. Open a pull request
