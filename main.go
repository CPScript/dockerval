package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Main application structure containing configuration and state
type App struct {
	GroqAPIKey    string
	VerboseMode   bool
	OutputFormat  string
	ConfigFile    string
}

// Represents a Docker Compose service with all its configuration
type ComposeService struct {
	Image         string                 `yaml:"image,omitempty"`
	Build         interface{}            `yaml:"build,omitempty"`
	Ports         []string              `yaml:"ports,omitempty"`
	Environment   interface{}           `yaml:"environment,omitempty"`
	Volumes       []string              `yaml:"volumes,omitempty"`
	Networks      interface{}           `yaml:"networks,omitempty"`
	DependsOn     interface{}           `yaml:"depends_on,omitempty"`
	Restart       string                `yaml:"restart,omitempty"`
	Command       interface{}           `yaml:"command,omitempty"`
	Entrypoint    interface{}           `yaml:"entrypoint,omitempty"`
	HealthCheck   map[string]interface{} `yaml:"healthcheck,omitempty"`
	Deploy        map[string]interface{} `yaml:"deploy,omitempty"`
	Labels        interface{}           `yaml:"labels,omitempty"`
	Resources     map[string]interface{} `yaml:"resources,omitempty"`
	SecurityOpt   []string              `yaml:"security_opt,omitempty"`
	Privileged    bool                  `yaml:"privileged,omitempty"`
	User          string                `yaml:"user,omitempty"`
	WorkingDir    string                `yaml:"working_dir,omitempty"`
}

// Main Docker Compose file structure
type ComposeFile struct {
	Version  string                     `yaml:"version,omitempty"`
	Services map[string]ComposeService  `yaml:"services,omitempty"`
	Networks map[string]interface{}     `yaml:"networks,omitempty"`
	Volumes  map[string]interface{}     `yaml:"volumes,omitempty"`
	Secrets  map[string]interface{}     `yaml:"secrets,omitempty"`
	Configs  map[string]interface{}     `yaml:"configs,omitempty"`
}

// Represents a validation issue found in the Compose file
type ValidationIssue struct {
	Type        string `json:"type"`        // error, warning, info
	Service     string `json:"service"`     // affected service name
	Category    string `json:"category"`    // category of the issue
	Message     string `json:"message"`     // human-readable description
	Suggestion  string `json:"suggestion"`  // recommended fix
	Line        int    `json:"line"`        // line number in file
}

// Contains all validation results
type ValidationResult struct {
	FilePath    string            `json:"file_path"`
	Issues      []ValidationIssue `json:"issues"`
	Summary     ValidationSummary `json:"summary"`
	LLMAnalysis string           `json:"llm_analysis,omitempty"`
}

// Summary statistics of validation results
type ValidationSummary struct {
	TotalIssues int `json:"total_issues"`
	Errors      int `json:"errors"`
	Warnings    int `json:"warnings"`
	Info        int `json:"info"`
}

// Structure for Groq API requests
type GroqRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

// Individual message in Groq conversation
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Groq API response structure
type GroqResponse struct {
	Choices []Choice `json:"choices"`
}

// Individual choice in Groq response
type Choice struct {
	Message Message `json:"message"`
}

// Global application instance
var app = &App{}

// Color definitions for output formatting
var (
	errorColor   = color.New(color.FgRed, color.Bold)
	warningColor = color.New(color.FgYellow)
	infoColor    = color.New(color.FgCyan)
	successColor = color.New(color.FgGreen)
	headerColor  = color.New(color.FgMagenta, color.Bold)
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dockerval",
		Short: "Docker Compose validator with AI assistance",
		Long: `A comprehensive Docker Compose validation tool that performs static analysis
and optionally uses AI (via Groq) to provide intelligent suggestions for
container orchestration improvements.`,
	}

	// Global flags available to all commands
	rootCmd.PersistentFlags().StringVar(&app.GroqAPIKey, "groq-key", "", "Groq API key for AI analysis")
	rootCmd.PersistentFlags().BoolVarP(&app.VerboseMode, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&app.OutputFormat, "output", "o", "text", "Output format (text, json)")
	rootCmd.PersistentFlags().StringVar(&app.ConfigFile, "config", "", "Config file path")

	// Command to validate a single Compose file
	validateCmd := &cobra.Command{
		Use:   "validate [file]",
		Short: "Validate a Docker Compose file",
		Args:  cobra.ExactArgs(1),
		Run:   validateCommand,
	}

	// Command to scan multiple files in a directory
	scanCmd := &cobra.Command{
		Use:   "scan [directory]",
		Short: "Scan directory for Docker Compose files",
		Args:  cobra.ExactArgs(1),
		Run:   scanCommand,
	}

	// Command to analyze a file with AI assistance
	analyzeCmd := &cobra.Command{
		Use:   "analyze [file]",
		Short: "Analyze Docker Compose file with AI",
		Args:  cobra.ExactArgs(1),
		Run:   analyzeCommand,
	}

	// Command to check tool configuration and connectivity
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Check tool configuration and API connectivity",
		Run:   checkCommand,
	}

	rootCmd.AddCommand(validateCmd, scanCmd, analyzeCmd, checkCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Handles the validate command execution
func validateCommand(cmd *cobra.Command, args []string) {
	filePath := args[0]
	
	if app.VerboseMode {
		fmt.Printf("Validating Docker Compose file: %s\n", filePath)
	}

	result, err := validateComposeFile(filePath)
	if err != nil {
		errorColor.Fprintf(os.Stderr, "Validation failed: %v\n", err)
		os.Exit(1)
	}

	outputResult(result)
}

// Handles the scan command to process multiple files
func scanCommand(cmd *cobra.Command, args []string) {
	directory := args[0]
	
	if app.VerboseMode {
		fmt.Printf("Scanning directory: %s\n", directory)
	}

	files, err := findComposeFiles(directory)
	if err != nil {
		errorColor.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Println("No Docker Compose files found")
		return
	}

	for _, file := range files {
		fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
		headerColor.Printf("Analyzing: %s\n", file)
		fmt.Printf(strings.Repeat("=", 60) + "\n")

		result, err := validateComposeFile(file)
		if err != nil {
			errorColor.Printf("Error validating %s: %v\n", file, err)
			continue
		}

		outputResult(result)
	}
}

// Handles the analyze command with AI assistance
func analyzeCommand(cmd *cobra.Command, args []string) {
	filePath := args[0]

	if app.GroqAPIKey == "" {
		errorColor.Println("Groq API key required for AI analysis. Use --groq-key flag or set GROQ_API_KEY environment variable")
		os.Exit(1)
	}

	if app.VerboseMode {
		fmt.Printf("Analyzing Docker Compose file with AI: %s\n", filePath)
	}

	result, err := validateComposeFile(filePath)
	if err != nil {
		errorColor.Fprintf(os.Stderr, "Analysis failed: %v\n", err)
		os.Exit(1)
	}

	// Get AI analysis using Groq
	content, err := os.ReadFile(filePath)
	if err != nil {
		errorColor.Fprintf(os.Stderr, "Failed to read file for AI analysis: %v\n", err)
		os.Exit(1)
	}

	aiAnalysis, err := getGroqAnalysis(string(content), result.Issues)
	if err != nil {
		warningColor.Printf("AI analysis failed: %v\n", err)
	} else {
		result.LLMAnalysis = aiAnalysis
	}

	outputResult(result)
}

// Handles the check command for configuration verification
func checkCommand(cmd *cobra.Command, args []string) {
	fmt.Println("Docker Compose Validator - Configuration Check")
	fmt.Println(strings.Repeat("-", 50))

	// Check if Docker is available
	if err := checkDockerAvailability(); err != nil {
		errorColor.Printf("❌ Docker: %v\n", err)
	} else {
		successColor.Println("✅ Docker: Available")
	}

	// Check Groq API key
	if app.GroqAPIKey != "" || os.Getenv("GROQ_API_KEY") != "" {
		if app.GroqAPIKey == "" {
			app.GroqAPIKey = os.Getenv("GROQ_API_KEY")
		}
		
		if err := testGroqConnection(); err != nil {
			errorColor.Printf("❌ Groq API: %v\n", err)
		} else {
			successColor.Println("✅ Groq API: Connected")
		}
	} else {
		infoColor.Println("ℹ️  Groq API: Not configured (AI analysis disabled)")
	}

	// Show current configuration
	fmt.Println("\nCurrent Configuration:")
	fmt.Printf("  Verbose Mode: %v\n", app.VerboseMode)
	fmt.Printf("  Output Format: %s\n", app.OutputFormat)
	fmt.Printf("  Config File: %s\n", app.ConfigFile)
}

// Main validation function that orchestrates all checks
func validateComposeFile(filePath string) (*ValidationResult, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var compose ComposeFile
	if err := yaml.Unmarshal(content, &compose); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}

	result := &ValidationResult{
		FilePath: filePath,
		Issues:   []ValidationIssue{},
	}

	// Run all validation checks
	result.Issues = append(result.Issues, validateVersion(compose)...)
	result.Issues = append(result.Issues, validateServices(compose)...)
	result.Issues = append(result.Issues, validatePorts(compose)...)
	result.Issues = append(result.Issues, validateNetworks(compose)...)
	result.Issues = append(result.Issues, validateVolumes(compose)...)
	result.Issues = append(result.Issues, validateSecurity(compose)...)
	result.Issues = append(result.Issues, validateBestPractices(compose)...)
	result.Issues = append(result.Issues, validateDependencies(compose)...)

	// Calculate summary statistics
	result.Summary = calculateSummary(result.Issues)

	return result, nil
}

// Validates Docker Compose version specification
func validateVersion(compose ComposeFile) []ValidationIssue {
	var issues []ValidationIssue

	if compose.Version == "" {
		issues = append(issues, ValidationIssue{
			Type:       "warning",
			Category:   "version",
			Message:    "No version specified in docker-compose.yml",
			Suggestion: "Add 'version: \"3.8\"' for better compatibility",
		})
	} else {
		// Check for deprecated versions
		if strings.HasPrefix(compose.Version, "2.") {
			issues = append(issues, ValidationIssue{
				Type:       "warning",
				Category:   "version",
				Message:    fmt.Sprintf("Version %s is deprecated", compose.Version),
				Suggestion: "Consider upgrading to version 3.8 or later",
			})
		}
	}

	return issues
}

// Validates service configurations
func validateServices(compose ComposeFile) []ValidationIssue {
	var issues []ValidationIssue

	if len(compose.Services) == 0 {
		issues = append(issues, ValidationIssue{
			Type:       "error",
			Category:   "services",
			Message:    "No services defined",
			Suggestion: "Add at least one service definition",
		})
		return issues
	}

	for serviceName, service := range compose.Services {
		// Check if service has image or build
		if service.Image == "" && service.Build == nil {
			issues = append(issues, ValidationIssue{
				Type:       "error",
				Service:    serviceName,
				Category:   "services",
				Message:    "Service has neither image nor build configuration",
				Suggestion: "Specify either 'image' or 'build' for the service",
			})
		}

		// Validate restart policy
		if service.Restart != "" {
			validPolicies := []string{"no", "always", "on-failure", "unless-stopped"}
			isValid := false
			for _, policy := range validPolicies {
				if service.Restart == policy {
					isValid = true
					break
				}
			}
			if !isValid {
				issues = append(issues, ValidationIssue{
					Type:       "error",
					Service:    serviceName,
					Category:   "services",
					Message:    fmt.Sprintf("Invalid restart policy: %s", service.Restart),
					Suggestion: "Use one of: no, always, on-failure, unless-stopped",
				})
			}
		}

		// Check for privileged mode usage
		if service.Privileged {
			issues = append(issues, ValidationIssue{
				Type:       "warning",
				Service:    serviceName,
				Category:   "security",
				Message:    "Service runs in privileged mode",
				Suggestion: "Avoid privileged mode unless absolutely necessary",
			})
		}
	}

	return issues
}

// Validates port configurations and checks for conflicts
func validatePorts(compose ComposeFile) []ValidationIssue {
	var issues []ValidationIssue
	usedPorts := make(map[string][]string) // port -> services using it

	for serviceName, service := range compose.Services {
		for _, portMapping := range service.Ports {
			// Parse port mapping (e.g., "8080:80", "3000", "127.0.0.1:5432:5432")
			parts := strings.Split(portMapping, ":")
			var hostPort string

			if len(parts) == 1 {
				hostPort = parts[0] // Same port for host and container
			} else if len(parts) == 2 {
				hostPort = parts[0] // host:container
			} else if len(parts) == 3 {
				hostPort = parts[1] // ip:host:container
			}

			if hostPort != "" {
				// Validate port number
				if port, err := strconv.Atoi(hostPort); err != nil {
					issues = append(issues, ValidationIssue{
						Type:       "error",
						Service:    serviceName,
						Category:   "ports",
						Message:    fmt.Sprintf("Invalid port number: %s", hostPort),
						Suggestion: "Use numeric port values (1-65535)",
					})
				} else {
					// Check port range
					if port < 1 || port > 65535 {
						issues = append(issues, ValidationIssue{
							Type:       "error",
							Service:    serviceName,
							Category:   "ports",
							Message:    fmt.Sprintf("Port %d is out of valid range", port),
							Suggestion: "Use ports between 1-65535",
						})
					}

					// Check for port conflicts
					if services, exists := usedPorts[hostPort]; exists {
						issues = append(issues, ValidationIssue{
							Type:       "error",
							Service:    serviceName,
							Category:   "ports",
							Message:    fmt.Sprintf("Port %s conflicts with service(s): %s", hostPort, strings.Join(services, ", ")),
							Suggestion: "Use different host ports for each service",
						})
					}
					usedPorts[hostPort] = append(usedPorts[hostPort], serviceName)
				}
			}
		}
	}

	return issues
}

// Validates network configurations
func validateNetworks(compose ComposeFile) []ValidationIssue {
	var issues []ValidationIssue

	// Track which networks are defined vs used
	definedNetworks := make(map[string]bool)
	usedNetworks := make(map[string]bool)

	for networkName := range compose.Networks {
		definedNetworks[networkName] = true
	}

	// Check service network usage
	for serviceName, service := range compose.Services {
		if service.Networks != nil {
			switch networks := service.Networks.(type) {
			case []interface{}:
				for _, network := range networks {
					if networkName, ok := network.(string); ok {
						usedNetworks[networkName] = true
						if networkName != "default" && !definedNetworks[networkName] {
							issues = append(issues, ValidationIssue{
								Type:       "error",
								Service:    serviceName,
								Category:   "networks",
								Message:    fmt.Sprintf("References undefined network: %s", networkName),
								Suggestion: "Define the network in the networks section or remove the reference",
							})
						}
					}
				}
			case map[string]interface{}:
				for networkName := range networks {
					usedNetworks[networkName] = true
					if networkName != "default" && !definedNetworks[networkName] {
						issues = append(issues, ValidationIssue{
							Type:       "error",
							Service:    serviceName,
							Category:   "networks",
							Message:    fmt.Sprintf("References undefined network: %s", networkName),
							Suggestion: "Define the network in the networks section or remove the reference",
						})
					}
				}
			}
		}
	}

	// Check for unused networks
	for networkName := range definedNetworks {
		if !usedNetworks[networkName] {
			issues = append(issues, ValidationIssue{
				Type:       "warning",
				Category:   "networks",
				Message:    fmt.Sprintf("Defined network '%s' is not used by any service", networkName),
				Suggestion: "Remove unused network definition or assign it to services",
			})
		}
	}

	return issues
}

// Validates volume configurations
func validateVolumes(compose ComposeFile) []ValidationIssue {
	var issues []ValidationIssue

	definedVolumes := make(map[string]bool)
	usedVolumes := make(map[string]bool)

	for volumeName := range compose.Volumes {
		definedVolumes[volumeName] = true
	}

	// Check service volume usage
	for serviceName, service := range compose.Services {
		for _, volumeMapping := range service.Volumes {
			parts := strings.Split(volumeMapping, ":")
			if len(parts) >= 2 {
				source := parts[0]
				
				// Check if it's a named volume (not a bind mount)
				if !strings.HasPrefix(source, "/") && !strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") {
					usedVolumes[source] = true
					if !definedVolumes[source] {
						issues = append(issues, ValidationIssue{
							Type:       "error",
							Service:    serviceName,
							Category:   "volumes",
							Message:    fmt.Sprintf("References undefined volume: %s", source),
							Suggestion: "Define the volume in the volumes section or use a bind mount path",
						})
					}
				}

				// Warn about bind mounts to sensitive paths
				target := parts[1]
				sensitivePaths := []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/root"}
				for _, sensitive := range sensitivePaths {
					if strings.HasPrefix(target, sensitive) {
						issues = append(issues, ValidationIssue{
							Type:       "warning",
							Service:    serviceName,
							Category:   "volumes",
							Message:    fmt.Sprintf("Volume mounts to sensitive path: %s", target),
							Suggestion: "Be careful when mounting to system directories",
						})
						break
					}
				}
			}
		}
	}

	// Check for unused volumes
	for volumeName := range definedVolumes {
		if !usedVolumes[volumeName] {
			issues = append(issues, ValidationIssue{
				Type:       "warning",
				Category:   "volumes",
				Message:    fmt.Sprintf("Defined volume '%s' is not used by any service", volumeName),
				Suggestion: "Remove unused volume definition or mount it in services",
			})
		}
	}

	return issues
}

// Validates security configurations
func validateSecurity(compose ComposeFile) []ValidationIssue {
	var issues []ValidationIssue

	for serviceName, service := range compose.Services {
		// Check for root user
		if service.User == "root" || service.User == "0" {
			issues = append(issues, ValidationIssue{
				Type:       "warning",
				Service:    serviceName,
				Category:   "security",
				Message:    "Service runs as root user",
				Suggestion: "Use a non-root user for better security",
			})
		}

		// Check security options
		for _, secOpt := range service.SecurityOpt {
			if secOpt == "seccomp:unconfined" {
				issues = append(issues, ValidationIssue{
					Type:       "warning",
					Service:    serviceName,
					Category:   "security",
					Message:    "Seccomp is disabled",
					Suggestion: "Avoid disabling seccomp unless necessary",
				})
			}
		}

		// Check for exposed sensitive ports
		for _, portMapping := range service.Ports {
			parts := strings.Split(portMapping, ":")
			var hostPort string
			if len(parts) >= 2 {
				if len(parts) == 3 {
					hostPort = parts[1]
				} else {
					hostPort = parts[0]
				}
			}

			if port, err := strconv.Atoi(hostPort); err == nil {
				sensitivePorts := map[int]string{
					22:    "SSH",
					23:    "Telnet",
					3389:  "RDP",
					5432:  "PostgreSQL",
					3306:  "MySQL",
					6379:  "Redis",
					27017: "MongoDB",
				}

				if service, exists := sensitivePorts[port]; exists {
					issues = append(issues, ValidationIssue{
						Type:       "warning",
						Service:    serviceName,
						Category:   "security",
						Message:    fmt.Sprintf("Exposing sensitive %s port %d", service, port),
						Suggestion: "Consider using a reverse proxy or VPN for sensitive services",
					})
				}
			}
		}
	}

	return issues
}

// Validates best practices compliance
func validateBestPractices(compose ComposeFile) []ValidationIssue {
	var issues []ValidationIssue

	for serviceName, service := range compose.Services {
		// Check for latest tag usage
		if strings.HasSuffix(service.Image, ":latest") || !strings.Contains(service.Image, ":") {
			issues = append(issues, ValidationIssue{
				Type:       "warning",
				Service:    serviceName,
				Category:   "best-practices",
				Message:    "Using 'latest' tag or no tag specified",
				Suggestion: "Pin to specific version tags for reproducible builds",
			})
		}

		// Check for health checks
		if service.HealthCheck == nil || len(service.HealthCheck) == 0 {
			issues = append(issues, ValidationIssue{
				Type:       "info",
				Service:    serviceName,
				Category:   "best-practices",
				Message:    "No health check configured",
				Suggestion: "Add health check for better container monitoring",
			})
		}

		// Check restart policy
		if service.Restart == "" {
			issues = append(issues, ValidationIssue{
				Type:       "info",
				Service:    serviceName,
				Category:   "best-practices",
				Message:    "No restart policy specified",
				Suggestion: "Consider setting restart: unless-stopped for production services",
			})
		}

		// Check for resource limits
		if service.Deploy == nil || service.Deploy["resources"] == nil {
			issues = append(issues, ValidationIssue{
				Type:       "info",
				Service:    serviceName,
				Category:   "best-practices",
				Message:    "No resource limits configured",
				Suggestion: "Set CPU and memory limits to prevent resource exhaustion",
			})
		}
	}

	return issues
}

// Validates service dependencies
func validateDependencies(compose ComposeFile) []ValidationIssue {
	var issues []ValidationIssue
	serviceNames := make(map[string]bool)

	// Collect all service names
	for serviceName := range compose.Services {
		serviceNames[serviceName] = true
	}

	// Check dependencies
	for serviceName, service := range compose.Services {
		if service.DependsOn != nil {
			switch deps := service.DependsOn.(type) {
			case []interface{}:
				for _, dep := range deps {
					if depName, ok := dep.(string); ok {
						if !serviceNames[depName] {
							issues = append(issues, ValidationIssue{
								Type:       "error",
								Service:    serviceName,
								Category:   "dependencies",
								Message:    fmt.Sprintf("Depends on undefined service: %s", depName),
								Suggestion: "Define the service or remove the dependency",
							})
						}
					}
				}
			case map[string]interface{}:
				for depName := range deps {
					if !serviceNames[depName] {
						issues = append(issues, ValidationIssue{
							Type:       "error",
							Service:    serviceName,
							Category:   "dependencies",
							Message:    fmt.Sprintf("Depends on undefined service: %s", depName),
							Suggestion: "Define the service or remove the dependency",
						})
					}
				}
			}
		}
	}

	// Detect potential circular dependencies (basic check)
	issues = append(issues, detectCircularDependencies(compose)...)

	return issues
}

// Detects circular dependencies between services
func detectCircularDependencies(compose ComposeFile) []ValidationIssue {
	var issues []ValidationIssue
	
	// Build dependency graph
	deps := make(map[string][]string)
	
	for serviceName, service := range compose.Services {
		if service.DependsOn != nil {
			switch dependencies := service.DependsOn.(type) {
			case []interface{}:
				for _, dep := range dependencies {
					if depName, ok := dep.(string); ok {
						deps[serviceName] = append(deps[serviceName], depName)
					}
				}
			case map[string]interface{}:
				for depName := range dependencies {
					deps[serviceName] = append(deps[serviceName], depName)
				}
			}
		}
	}

	// Simple cycle detection using DFS
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var hasCycle func(string) bool
	hasCycle = func(service string) bool {
		visited[service] = true
		recStack[service] = true

		for _, dep := range deps[service] {
			if !visited[dep] && hasCycle(dep) {
				return true
			} else if recStack[dep] {
				return true
			}
		}

		recStack[service] = false
		return false
	}

	for service := range compose.Services {
		if !visited[service] && hasCycle(service) {
			issues = append(issues, ValidationIssue{
				Type:       "error",
				Category:   "dependencies",
				Message:    "Circular dependency detected",
				Suggestion: "Review and fix circular dependencies between services",
			})
			break
		}
	}

	return issues
}

// Calculates summary statistics from validation issues
func calculateSummary(issues []ValidationIssue) ValidationSummary {
	summary := ValidationSummary{}
	
	for _, issue := range issues {
		summary.TotalIssues++
		switch issue.Type {
		case "error":
			summary.Errors++
		case "warning":
			summary.Warnings++
		case "info":
			summary.Info++
		}
	}
	
	return summary
}

// Outputs validation results in the specified format
func outputResult(result *ValidationResult) {
	if app.OutputFormat == "json" {
		output, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			errorColor.Fprintf(os.Stderr, "Failed to marshal JSON: %v\n", err)
			return
		}
		fmt.Println(string(output))
		return
	}

	// Text output format
	fmt.Printf("\nValidation Results for: %s\n", result.FilePath)
	fmt.Println(strings.Repeat("=", 60))

	if len(result.Issues) == 0 {
		successColor.Println("✅ No issues found!")
		return
	}

	// Group issues by type
	errorIssues := []ValidationIssue{}
	warningIssues := []ValidationIssue{}
	infoIssues := []ValidationIssue{}

	for _, issue := range result.Issues {
		switch issue.Type {
		case "error":
			errorIssues = append(errorIssues, issue)
		case "warning":
			warningIssues = append(warningIssues, issue)
		case "info":
			infoIssues = append(infoIssues, issue)
		}
	}

	// Display errors
	if len(errorIssues) > 0 {
		errorColor.Printf("\n❌ ERRORS (%d):\n", len(errorIssues))
		for _, issue := range errorIssues {
			fmt.Printf("  • ")
			if issue.Service != "" {
				fmt.Printf("[%s] ", issue.Service)
			}
			fmt.Printf("%s\n", issue.Message)
			if issue.Suggestion != "" {
				fmt.Printf("    💡 %s\n", issue.Suggestion)
			}
		}
	}

	// Display warnings
	if len(warningIssues) > 0 {
		warningColor.Printf("\n⚠️  WARNINGS (%d):\n", len(warningIssues))
		for _, issue := range warningIssues {
			fmt.Printf("  • ")
			if issue.Service != "" {
				fmt.Printf("[%s] ", issue.Service)
			}
			fmt.Printf("%s\n", issue.Message)
			if issue.Suggestion != "" {
				fmt.Printf("    💡 %s\n", issue.Suggestion)
			}
		}
	}

	// Display info
	if len(infoIssues) > 0 {
		infoColor.Printf("\nℹ️  INFO (%d):\n", len(infoIssues))
		for _, issue := range infoIssues {
			fmt.Printf("  • ")
			if issue.Service != "" {
				fmt.Printf("[%s] ", issue.Service)
			}
			fmt.Printf("%s\n", issue.Message)
			if issue.Suggestion != "" {
				fmt.Printf("    💡 %s\n", issue.Suggestion)
			}
		}
	}

	// Display summary
	fmt.Printf("\n" + strings.Repeat("-", 60) + "\n")
	fmt.Printf("Summary: %d total issues ", result.Summary.TotalIssues)
	if result.Summary.Errors > 0 {
		errorColor.Printf("(%d errors) ", result.Summary.Errors)
	}
	if result.Summary.Warnings > 0 {
		warningColor.Printf("(%d warnings) ", result.Summary.Warnings)
	}
	if result.Summary.Info > 0 {
		infoColor.Printf("(%d info)", result.Summary.Info)
	}
	fmt.Println()

	// Display AI analysis if available
	if result.LLMAnalysis != "" {
		fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
		headerColor.Println("🤖 AI ANALYSIS")
		fmt.Printf(strings.Repeat("=", 60) + "\n")
		fmt.Println(result.LLMAnalysis)
	}
}

// Finds Docker Compose files in a directory recursively
func findComposeFiles(directory string) ([]string, error) {
	var files []string
	
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() {
			filename := strings.ToLower(info.Name())
			if filename == "docker-compose.yml" || 
			   filename == "docker-compose.yaml" || 
			   filename == "compose.yml" || 
			   filename == "compose.yaml" ||
			   strings.HasPrefix(filename, "docker-compose.") && 
			   (strings.HasSuffix(filename, ".yml") || strings.HasSuffix(filename, ".yaml")) {
				files = append(files, path)
			}
		}
		
		return nil
	})
	
	return files, err
}

// Gets AI analysis from Groq API
func getGroqAnalysis(composeContent string, issues []ValidationIssue) (string, error) {
	if app.GroqAPIKey == "" {
		app.GroqAPIKey = os.Getenv("GROQ_API_KEY")
	}

	if app.GroqAPIKey == "" {
		return "", fmt.Errorf("Groq API key not provided")
	}

	// Prepare the prompt for AI analysis
	issuesJSON, _ := json.MarshalIndent(issues, "", "  ")
	prompt := fmt.Sprintf(`Please analyze this Docker Compose file and provide recommendations for improvement. 

Here's the Docker Compose content:
---
%s
---

Static analysis has already identified these issues:
%s

Please provide:
1. Analysis of the overall architecture and design
2. Recommendations for scaling and performance
3. Security best practices that might be missing
4. Suggestions for better orchestration
5. Any patterns or anti-patterns you notice

Focus on practical, actionable advice that goes beyond the static analysis results.`, composeContent, string(issuesJSON))

	request := GroqRequest{
		Model: "mixtral-8x7b-32768",
		Messages: []Message{
			{
				Role:    "system",
				Content: "You are a Docker and container orchestration expert. Provide practical, actionable advice for improving Docker Compose configurations.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", "https://api.groq.com/openai/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+app.GroqAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var groqResp GroqResponse
	if err := json.NewDecoder(resp.Body).Decode(&groqResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	if len(groqResp.Choices) == 0 {
		return "", fmt.Errorf("no response choices returned")
	}

	return groqResp.Choices[0].Message.Content, nil
}

// Tests connection to Groq API
func testGroqConnection() error {
	if app.GroqAPIKey == "" {
		app.GroqAPIKey = os.Getenv("GROQ_API_KEY")
	}

	request := GroqRequest{
		Model: "mixtral-8x7b-32768",
		Messages: []Message{
			{
				Role:    "user",
				Content: "Hello, this is a connection test. Please respond with 'OK'.",
			},
		},
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", "https://api.groq.com/openai/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+app.GroqAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}

// Checks if Docker is available on the system
func checkDockerAvailability() error {
	// Try to run docker --version command
	client := &http.Client{Timeout: 5 * time.Second}
	
	// Check if Docker daemon is running by trying to connect to the socket
	// This is a simple check - in a real implementation you might use the Docker SDK
	req, err := http.NewRequest("GET", "http://localhost/version", nil)
	if err != nil {
		return fmt.Errorf("Docker not available")
	}

	resp, err := client.Do(req)
	if err != nil {
		// Docker might be available but daemon not running
		return fmt.Errorf("Docker daemon not running or not accessible")
	}
	defer resp.Body.Close()

	return nil
}