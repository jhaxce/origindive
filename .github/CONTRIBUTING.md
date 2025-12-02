# Contributing to originfind

Thank you for your interest in contributing! This document provides guidelines for contributing to originfind.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check the [existing issues](https://github.com/jhaxce/originfind/issues) to avoid duplicates
2. Use the latest version to verify the bug still exists

When creating a bug report, include:
- **Description**: Clear description of the issue
- **Steps to Reproduce**: Exact steps to trigger the bug
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: OS, Go version, terminal type
- **Command**: The exact command you ran
- **Output**: Error messages or logs

Example:
```
**Bug**: Colors not displaying in PowerShell
**OS**: Windows 10
**Go**: 1.21
**Command**: `./originfind -d example.com -n 192.168.1.0/24`
**Expected**: Colored output
**Actual**: Plain text output
```

### Suggesting Features

Feature requests are welcome! Please:
1. Check existing issues for similar requests
2. Clearly describe the feature and its use case
3. Explain why it would be useful
4. Provide examples if possible

### Submitting Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**:
   - Follow the existing code style
   - Add comments for complex logic
   - Keep changes focused (one feature per PR)
4. **Test your changes**:
   ```bash
   go build -o originfind originfind.go
   ./originfind -d example.com -n 192.168.1.0/28
   ```
5. **Commit** with clear messages:
   ```bash
   git commit -m "Add support for IPv6 scanning"
   ```
6. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request** with:
   - Clear title and description
   - Reference related issues
   - Screenshots/examples if applicable

## Development Guidelines

### Code Style

- Follow standard Go formatting (`gofmt`)
- Use meaningful variable names
- Add comments for non-obvious code
- Keep functions focused and small
- Use existing code patterns

### Code Structure

```go
// Good: Clear function with documentation
// parseIP converts a string IP to uint32 representation
func parseIP(ip string) (uint32, error) {
    // Implementation
}

// Bad: No documentation, unclear purpose
func p(s string) uint32 {
    // Implementation
}
```

### Testing

Before submitting:
```bash
# Build successfully
go build -o originfind originfind.go

# Test basic functionality
./originfind -d example.com -n 192.168.1.0/28 -j 5

# Test edge cases
./originfind -d example.com -s 192.168.1.1 -e 192.168.1.1
./originfind -d example.com -i test.txt -n /32
```

### Documentation

Update documentation when:
- Adding new features
- Changing command-line flags
- Modifying behavior
- Fixing bugs that affect usage

Files to update:
- `README.md` - User-facing documentation
- `CHANGELOG.md` - Version history
- Code comments - Internal documentation
- `originfind.go` usage() function - Help text

## What We're Looking For

### High Priority
- Bug fixes
- Performance improvements
- Better error handling
- Cross-platform compatibility
- Documentation improvements

### Welcome Additions
- New input methods
- Output formats (JSON, CSV)
- Additional HTTP features
- Better terminal detection
- Testing improvements

### Not Accepting
- Features requiring external dependencies (keep it stdlib only)
- Overly complex features
- Breaking changes without strong justification
- Style-only changes without functional improvements

## Code Review Process

1. Maintainer reviews PR within a few days
2. Feedback is provided if changes needed
3. Once approved, PR is merged
4. You'll be credited in CHANGELOG.md

## First Time Contributors

Welcome! Here are good first issues:
- Documentation typos
- Adding examples
- Improving error messages
- Small bug fixes
- Code comments

Look for issues labeled `good first issue` or `help wanted`.

## Questions?

- Open an issue for general questions
- Reference relevant code/documentation
- Be patient - this is maintained by volunteers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to originfind!**
