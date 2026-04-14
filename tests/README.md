# Tests

This folder contains all testing resources for the CS 419 Secure Document Sharing System.

## Files

| File | Description |
|---|---|
| `test_app.py` | 103 automated tests covering all rubric requirements |
| `MANUAL_TESTING.md` | Step-by-step manual testing guide (browser + terminal) |

## Running the automated tests

```bash
# From the project root — activate venv first
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

# Install pytest if not already installed
pip install pytest

# Run all 103 tests
python -m pytest tests/test_app.py -v

# Run a specific section
python -m pytest tests/test_app.py::TestLogin -v
python -m pytest tests/test_app.py::TestSecurityHeaders -v
python -m pytest tests/test_app.py::TestAccessControl -v
python -m pytest tests/test_app.py::TestEncryption -v
python -m pytest tests/test_app.py::TestSessionManagement -v
python -m pytest tests/test_app.py::TestLogging -v
python -m pytest tests/test_app.py::TestDocumentFeatures -v

# Stop on first failure
python -m pytest tests/test_app.py -x -v
```

## Test coverage by rubric section

| Test class | Rubric section | Tests |
|---|---|---|
| `TestRegistrationValidation` | A. Authentication — registration | 17 |
| `TestLogin` | A. Authentication — login | 12 |
| `TestAccessControl` | B. Access Control | 14 |
| `TestInputValidation` | C. Input Validation & Injection | 14 |
| `TestEncryption` | D. Encryption | 4 |
| `TestSessionManagement` | E. Session Management | 10 |
| `TestSecurityHeaders` | F. Security Headers | 10 |
| `TestLogging` | G. Logging & Monitoring | 12 |
| `TestDocumentFeatures` | Core features | 8 |
| **Total** | | **103** |

## Manual testing

See [MANUAL_TESTING.md](MANUAL_TESTING.md) for step-by-step instructions to
verify each requirement by hand in the browser and terminal.
