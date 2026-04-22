# Tests

This folder contains all testing resources for the CS 419 Secure Document Sharing System.

## Files

| File | Description |
|---|---|
| `test_app.py` | 140 automated tests covering every rubric section and document workflow |

## Running the automated tests

```bash
# From the project root — activate venv first
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

# Install pytest if not already installed
pip install pytest

# Run all automated tests
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
| `TestRegistrationValidation` | A. Authentication — registration | 19 |
| `TestLogin` | A. Authentication — login | 13 |
| `TestPasswordChange` | A. Authentication — password change | 3 |
| `TestAccessControl` | B. Access Control | 20 |
| `TestInputValidation` | C. Input Validation & Injection | 19 |
| `TestEncryption` | D. Encryption | 4 |
| `TestSessionManagement` | E. Session Management | 10 |
| `TestSecurityHeaders` | F. Security Headers | 10 |
| `TestLogging` | G. Logging & Monitoring | 25 |
| `TestDocumentFeatures` | Core features | 17 |
| **Total** | | **140** |