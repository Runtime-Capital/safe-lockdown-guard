SHELL := /usr/bin/env bash
ECHIDNA_IMAGE := trailofbits/echidna@sha256:8546f6705d46aea2cdf8309a251ad0946c7f92b7d3eb0b968fba37e3afbf131c

.PHONY: help hooks format test build contract-sizes webauthn-fixtures embedded-bytecode build-info sourcify-rehearsal coverage slither aderyn semgrep halmos browser-smoke echidna medusa mutation-gambit audit-check audit-check-full package clean

help:
	@printf '%s\n' 'safe-lockdown commands:'
	@printf '%s\n' '  make hooks               Enable tracked git hooks (forge fmt --check on commit)'
	@printf '%s\n' '  make format              Format Solidity sources with forge fmt'
	@printf '%s\n' '  make test                Run Foundry unit tests'
	@printf '%s\n' '  make build               Build contracts'
	@printf '%s\n' '  make contract-sizes      Show artifact-derived runtime sizes'
	@printf '%s\n' '  make webauthn-fixtures   Generate Foundry tests from captured browser WebAuthn fixtures'
	@printf '%s\n' '  make embedded-bytecode   Check local deployment helper bytecode'
	@printf '%s\n' '  make build-info          Build with Foundry build-info artifacts'
	@printf '%s\n' '  make sourcify-rehearsal  Dry-run or execute Sourcify verification flow'
	@printf '%s\n' '  make coverage            Run coverage summary'
	@printf '%s\n' '  make slither             Run Slither static analysis'
	@printf '%s\n' '  make aderyn              Run Aderyn static analysis if installed'
	@printf '%s\n' '  make semgrep             Run Semgrep registry + Safe guard rules if available'
	@printf '%s\n' '  make halmos              Run focused Halmos symbolic checks'
	@printf '%s\n' '  make browser-smoke       Run Playwright smoke test for lockdown-lifecycle.html'
	@printf '%s\n' '  make echidna             Run Echidna property tests via Docker'
	@printf '%s\n' '  make medusa              Run optional Medusa fuzz campaign if installed'
	@printf '%s\n' '  make mutation-gambit     Run optional targeted Gambit mutation pass'
	@printf '%s\n' '  make audit-check         Run required local checks'
	@printf '%s\n' '  make audit-check-full    Run required + optional heavy checks'
	@printf '%s\n' '  make package             Optional: create clean source snapshot (excludes generated + local files)'

hooks:
	git config core.hooksPath .githooks
	@printf '%s\n' 'Enabled tracked git hooks (core.hooksPath = .githooks).'

format:
	forge fmt

test:
	forge test

build:
	forge build

webauthn-fixtures:
	node scripts/webauthn-fixture-to-sol.js

embedded-bytecode:
	scripts/check-embedded-bytecode.sh

build-info:
	scripts/build-reproducibility.sh

sourcify-rehearsal:
	scripts/sourcify-rehearsal.sh

coverage:
	forge coverage --ir-minimum --report summary

slither:
	slither . --compile-force-framework foundry --filter-paths "test|script|lib" --exclude timestamp,assembly,naming-convention --fail-none

aderyn:
	@if command -v aderyn >/dev/null 2>&1; then \
		aderyn . -s src -o /tmp/safe-lockdown-aderyn.md; \
	else \
		echo 'aderyn not installed; skipping'; \
	fi

semgrep:
	scripts/semgrep-safe-guard.sh

halmos:
	forge clean
	halmos --match-contract LockdownHalmosTest --solver-timeout-assertion 20s --width 64 --depth 0 --no-status

browser-smoke:
	scripts/browser-smoke-lockdown-lifecycle.sh

# The pinned pip upgrade works around a stale crytic-compile (0.3.11) in the
# current trailofbits/echidna image: it cannot parse the build-info format
# of the image's own forge 1.5.1 (KeyError: 'output'). This target only runs
# Echidna; the host-side Slither target retains its own compatible dependency.
# Drop the override once the pinned image ships a fixed crytic-compile.
echidna:
	docker run --rm --memory 6g --memory-swap 6g -v "$$PWD":/src -w /src "$(ECHIDNA_IMAGE)" \
		sh -c "/venv/bin/pip install -q --no-deps --upgrade 'crytic-compile==0.4.1' && \
		echidna test/echidna/EchidnaLockdown.sol \
		--contract EchidnaLockdown \
		--config test/echidna/echidna.yaml"
	@if command -v docker >/dev/null 2>&1 \
		&& ! docker info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -q rootless; then \
		docker run --rm -v "$$PWD":/src -w /src "$(ECHIDNA_IMAGE)" \
			chown -R "$$(id -u):$$(id -g)" out cache crytic-export test/echidna/corpus 2>/dev/null || true; \
	fi

medusa:
	scripts/medusa-fuzz.sh

mutation-gambit:
	scripts/mutation-gambit.sh

contract-sizes:
	scripts/contract-sizes.sh

audit-check: test build

audit-check-full: test build build-info contract-sizes sourcify-rehearsal coverage slither aderyn semgrep halmos browser-smoke echidna medusa mutation-gambit

operator-check:
	scripts/operator-check.sh

package:
	scripts/package-audit.sh

clean:
	forge clean
	rm -rf crytic-export test/echidna/corpus test/echidna/covered.*.html test/echidna/crytic-export reproducibility medusa-corpus
