"""Support `python -m hydra` when the checkout directory is named hydra."""

try:
    from .hydra_cli import main
except ImportError:  # direct execution from a source checkout
    from hydra_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
