# Contributing to AuthenticationAPI

Thank you for your interest in contributing! We welcome contributions from the community.

## Development Setup

1.  **Prerequisites**:
    - Python 3.12+
    - [Poetry](https://python-poetry.org/)

2.  **Install Dependencies**:
    ```bash
    poetry install
    ```

3.  **Run Tests**:
    ```bash
    poetry run pytest
    ```

4.  **Formatting & Linting**:
    `ruff` is used for linting and formatting.
    ```bash
    poetry run ruff format .
    poetry run ruff check . --fix
    ```

## Submitting Pull Requests

1.  Fork the repository.
2.  Create a new branch for your feature (`git checkout -b feature/amazing-feature`).
3.  Commit your changes.
4.  Push to the branch.
5.  Open a Pull Request.

## Code Style

- All code must be typed (`mypy` is used to check).
- All new features must include tests.
- Follow the existing project structure.
