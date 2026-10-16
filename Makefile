LAB     := terraform/envs/lab
ACCOUNT := terraform/envs/account
NAME    ?= detlab
VENV    := .venv
PY      := $(VENV)/bin/python
DEPS    := $(VENV)/.installed
# stratus from PATH, else where `go install` puts it.
STRATUS ?= $(shell command -v stratus 2>/dev/null || echo "$$(go env GOPATH 2>/dev/null || echo $(HOME)/go)/bin/stratus")

.PHONY: help venv test test-patterns-live fmt validate account lab-plan lab-apply lab-destroy set-slack-webhook smoke-test attack

help:
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-20s %s\n", $$1, $$2}'

# Project virtualenv (Arch and other PEP 668 distros block system-wide pip).
# Rebuilt automatically whenever requirements-dev.txt changes.
$(DEPS): requirements-dev.txt
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -r requirements-dev.txt
	@touch $(DEPS)

venv: $(DEPS) ## Create the Python virtualenv (.venv) with boto3 and pytest

test: $(DEPS) ## Unit tests for responders and rule patterns (offline)
	$(PY) -m pytest -q

test-patterns-live: $(DEPS) ## Check fixtures against the real EventBridge matcher (needs AWS creds)
	$(PY) detections/test_patterns_live.py

fmt: ## Format Terraform
	terraform fmt -recursive terraform

validate: ## Validate both Terraform roots
	cd $(ACCOUNT) && terraform init -backend=false -input=false >/dev/null && terraform validate
	cd $(LAB) && terraform init -backend=false -input=false >/dev/null && terraform validate

account: ## Apply the permanent account baseline (Phase 2)
	cd $(ACCOUNT) && terraform init -input=false && terraform apply

lab-plan: ## Plan the lab (telemetry + detections + workload)
	cd $(LAB) && terraform init -input=false && terraform plan

lab-apply: ## Deploy the lab
	cd $(LAB) && terraform init -input=false && terraform apply

lab-destroy: ## Tear the lab down at the end of a session
	cd $(LAB) && terraform destroy

set-slack-webhook: ## Store the Slack webhook in SSM without it touching shell history or Terraform state
	@read -s -p "Paste Slack webhook URL: " url; echo; \
	aws ssm put-parameter --name /$(NAME)/slack-webhook-url --type SecureString --overwrite --value "$$url" >/dev/null && \
	echo "Stored. The next alert will use it."

smoke-test: ## Generate a GuardDuty sample finding; expect a DL-006 Slack alert within ~1 min
	aws guardduty create-sample-findings \
	  --detector-id $$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
	  --finding-types 'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS'

attack: $(DEPS) ## Run Phase 5 attack validation (ACCOUNT_ID=123456789012)
	@test -n "$(ACCOUNT_ID)" || (echo "usage: make attack ACCOUNT_ID=<lab account id>" && exit 1)
	@test -x "$(STRATUS)" || (echo "stratus not found at $(STRATUS); pass STRATUS=/path/to/stratus" && exit 1)
	STRATUS_BIN="$(STRATUS)" $(PY) attack-sim/validate.py --account-id $(ACCOUNT_ID)
