.PHONY: help setup localstack-up localstack-down terraform-up terraform-down scan test lint clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Install project dependencies
	pip install -e ".[dev]"

localstack-up: ## Start LocalStack via Docker Compose
	docker-compose up -d
	@echo "Waiting for LocalStack to be ready..."
	@sleep 5

localstack-down: ## Stop LocalStack
	docker-compose down -v

terraform-up: localstack-up ## Provision vulnerable resources in LocalStack
	cd terraform && terraform init && terraform apply -auto-approve

terraform-down: ## Destroy Terraform resources
	cd terraform && terraform destroy -auto-approve

scan: ## Run CSPM scan against LocalStack
	cspm scan --config config/default.yaml --output console --remediation

scan-all: ## Run scan with all output formats
	cspm scan --config config/default.yaml --output all --remediation --compare-previous

test: ## Run all tests
	pytest tests/ -v --tb=short

test-unit: ## Run unit tests only
	pytest tests/unit/ -v --tb=short

test-integration: localstack-up ## Run integration tests against LocalStack
	pytest tests/integration/ -v --tb=short

lint: ## Run linter
	ruff check src/ tests/

lint-fix: ## Run linter with auto-fix
	ruff check --fix src/ tests/

demo: localstack-up terraform-up scan ## Full demo: start LocalStack, provision resources, scan

clean: localstack-down ## Clean up everything
	rm -f cspm_findings.db
	rm -f cspm_report_*.json cspm_report_*.html
