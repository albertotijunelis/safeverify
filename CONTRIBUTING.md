# Contributing to HashGuard

Thank you for your interest in contributing! Here's how to get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/albertotijunelis/hashguard.git
cd hashguard

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux / macOS

# Install in editable mode with dev + test extras
pip install -e ".[dev,test]"
```

## Running Tests

```bash
pytest                          # run all tests
pytest --cov=hashguard -q      # with coverage
pytest tests/test_scanner.py    # run a specific file
```

## Code Style

- Formatting: [Black](https://black.readthedocs.io/) with 100-char line length
- Linting: [Pylint](https://pylint.readthedocs.io/)
- Type checking: [Mypy](https://mypy.readthedocs.io/) (optional)

```bash
black src/ tests/       # auto-format
pylint src/hashguard/  # lint
mypy src/hashguard/    # type-check
```

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Write tests for any new functionality.
3. Ensure `pytest` passes and `black --check src/ tests/` reports no changes.
4. Open a pull request with a clear description of the change.
5. Keep commits focused — one logical change per commit.

## Adding YARA Rules

Place new `.yar` files in `yara_rules/`. Each rule should include `meta` with at least:

```yara
rule Example_Detection {
    meta:
        description = "What this rule detects"
        severity = "medium"   // low | medium | high | critical
        author = "Your Name"
    strings:
        $s1 = "pattern"
    condition:
        $s1
}
```

## Reporting Issues

Use [GitHub Issues](https://github.com/albertotijunelis/hashguard/issues) for bugs and feature requests. For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).
