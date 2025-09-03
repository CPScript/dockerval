# Docker Compose Validator (dockerval)

A Docker Compose validation tool that performs static analysis and optionally uses AI (via Groq) to provide intelligent suggestions for container orchestration improvements.

## Features

### Core Validation
- **Version Compatibility**: Checks Docker Compose version specifications and warns about deprecated versions
- **Service Configuration**: Validates service definitions, image specifications, and restart policies
- **Port Management**: Detects port conflicts and validates port ranges
- **Network Analysis**: Ensures network references are properly defined and identifies unused networks
- **Volume Validation**: Checks volume definitions and warns about sensitive path mounts
- **Security Checks**: Identifies security risks like privileged containers, root users, and exposed sensitive ports
- **Best Practices**: Enforces Docker best practices including tagged images, health checks, and resource limits
- **Dependency Analysis**: Validates service dependencies and detects circular dependencies

### AI Integration
- **Groq LLM Integration**: Optional AI-powered analysis for advanced insights
- **Architecture Analysis**: AI reviews overall compose file structure and suggests improvements
- **Performance Recommendations**: Scaling and optimization suggestions
- **Security Insights**: Advanced security recommendations beyond static analysis

### Output Options
- **Multiple Formats**: Text and JSON output formats
- **Color-Coded Results**: Clear visual distinction between errors, warnings, and info
- **Detailed Suggestions**: Each issue includes actionable remediation advice

## Installation

### Prerequisites
- Go 1.21 or later
- Docker (for connectivity checks)
- Groq API key (optional, for AI analysis)

### Build from Source

```bash
# Clone or create the project
mkdir dockerval && cd dockerval

# Initialize the module
go mod init dockerval

# Copy the main.go file
# ... (copy the main code)

# Install dependencies
go mod tidy

# Build the binary
go build -o dockerval main.go
```

### Install Binary
```bash
# Make it executable and move to PATH
chmod +x dockerval
sudo mv dockerval /usr/local/bin/
```

## Configuration

### Environment Variables
```bash
export GROQ_API_KEY="your-groq-api-key-here"
```

### Command Line Options
- `--groq-key`: Groq API key for AI analysis
- `--verbose, -v`: Enable verbose output
- `--output, -o`: Output format (text, json)
- `--config`: Configuration file path

## Usage

### Basic Validation
```bash
# Validate a single Docker Compose file
dockerval validate docker-compose.yml

# Validate with verbose output
dockerval validate -v docker-compose.yml

# Output results in JSON format
dockerval validate -o json docker-compose.yml
```

### Directory Scanning
```bash
# Scan directory for all compose files
dockerval scan ./projects

# Scan current directory
dockerval scan .
```

### AI-Powered Analysis
```bash
# Analyze with AI assistance (requires Groq API key)
dockerval analyze --groq-key YOUR_API_KEY docker-compose.yml

# Using environment variable
export GROQ_API_KEY=your_key
dockerval analyze docker-compose.yml
```

### System Check
```bash
# Check tool configuration and connectivity
dockerval check
```

## Examples

### Sample Docker Compose Issues

The tool detects various types of issues:

**Port Conflicts:**
```yaml
services:
  web1:
    image: nginx
    ports:
      - "8080:80"
  web2:
    image: apache
    ports:
      - "8080:80"  # ❌ Port conflict detected
```

**Security Issues:**
```yaml
services:
  app:
    image: myapp:latest  # ⚠️ Using latest tag
    privileged: true     # ⚠️ Privileged mode
    user: root          # ⚠️ Root user
    ports:
      - "22:22"         # ⚠️ Exposing SSH port
```

**Dependency Problems:**
```yaml
services:
  web:
    image: nginx
    depends_on:
      - nonexistent     # ❌ Undefined service
  
  api:
    image: api
    depends_on:
      - web
  
  web:
    depends_on:
      - api             # ❌ Circular dependency
```

### Sample Output

<img width="668" height="416" alt="image" src="https://github.com/user-attachments/assets/6ac6f655-e4c9-4d9d-be77-f437f52b7cc1" />


```
Validation Results for: example/example_compose.yml
============================================================

⚠️  WARNINGS (5):
  • [database] Volume mounts to sensitive path: /etc/postgresql/postgresql.conf
    💡 Be careful when mounting to system directories
  • [redis] Volume mounts to sensitive path: /usr/local/etc/redis/redis.conf
    💡 Be careful when mounting to system directories
  • [nginx] Volume mounts to sensitive path: /etc/nginx/conf.d
    💡 Be careful when mounting to system directories
  • [nginx] Volume mounts to sensitive path: /etc/ssl
    💡 Be careful when mounting to system directories
  • [nginx] Volume mounts to sensitive path: /usr/share/nginx/html
    💡 Be careful when mounting to system directories

------------------------------------------------------------
```

## Validation Categories

### Errors (❌)
Critical issues that will likely cause deployment failures:
- Missing image or build configuration
- Port conflicts
- Invalid port numbers
- Undefined network/volume references
- Circular dependencies

### Warnings (⚠️)
Issues that should be addressed for production readiness:
- Security vulnerabilities
- Deprecated configurations
- Using latest tags
- Privileged containers
- Exposed sensitive ports

### Info (ℹ️)
Best practice recommendations for optimization:
- Missing health checks
- No resource limits
- No restart policy
- Missing monitoring setup

## Integration

### CI/CD Pipeline Integration
```bash
# Add to your CI pipeline
dockerval validate docker-compose.yml --output json > validation-results.json

# Exit with error code if critical issues found
if dockerval validate docker-compose.yml | grep -q "❌"; then
  echo "Critical issues found in Docker Compose file"
  exit 1
fi
```

### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit
find . -name "docker-compose*.yml" -exec dockerval validate {} \;
```

## Development

### Project Structure
```
dockerval/
├── main.go              # Main application code
├── go.mod              # Go module definition
├── go.sum              # Dependency checksums
├── README.md           # Project documentation
└── examples/           # Example compose files
```

### Adding New Validators

To add a new validation rule:

1. Create a new validation function following the pattern:
```go
func validateNewFeature(compose ComposeFile) []ValidationIssue {
    var issues []ValidationIssue
    // Your validation logic here
    return issues
}
```

2. Add it to the main validation pipeline in `validateComposeFile()`:
```go
result.Issues = append(result.Issues, validateNewFeature(compose)...)
```

### Testing

Create test compose files in the `examples/` directory to test various scenarios:

```bash
# Test with problematic compose file
dockerval validate examples/problematic-compose.yml

# Test with good compose file
dockerval validate examples/good-compose.yml
```

## API Reference

### Groq Integration

The tool uses Groq's API for AI analysis. The default model is `mixtral-8x7b-32768` which provides good performance for code analysis tasks.

API endpoint: `https://api.groq.com/openai/v1/chat/completions`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your validation logic
4. Test with various compose files
5. Submit a pull request

## License

MIT License - feel free to use and modify for your projects.

## Troubleshooting

### Common Issues

**"Groq API key required"**
- Set the `GROQ_API_KEY` environment variable
- Or use the `--groq-key` flag

**"Docker daemon not running"**
- Start Docker daemon: `sudo systemctl start docker`
- Or run without Docker connectivity check

**"Failed to parse YAML"**
- Check YAML syntax in your compose file
- Ensure proper indentation

**"No Docker Compose files found"**
- Ensure files are named correctly (docker-compose.yml, compose.yml, etc.)
- Check if files exist in the specified directory

### Performance Tips

- Use `--verbose` flag for detailed progress information
- JSON output is faster for programmatic processing

- Directory scans can be slow with many nested directories
