# tincstack — verification entry points (M9). Everything runs in Docker;
# nothing is installed on the host. `make check` is the one CI command.
#
#   make check          build core + baseline images, two-node YAML smoke test,
#                       NAT lab quick subset (core), dpi-proof baseline capture
#   make nat-full       the whole NAT matrix, core and baseline (~40 min)
#   make laptop         the CGNAT / sleep-resume regression, core vs baseline
#   make dpi-baseline   capture plain tinc and assert its fingerprints
#   make lint           shellcheck every shell script (in a container)
#   make promote        copy the curated evidence of one run into the committed
#                       results/<DATE>/ trees (RUN=<run-id> [DATE=<YYYY-MM-DD>])
#
# TAG selects the image tag family (tincstack/core:$(TAG), tincstack/baseline:$(TAG),
# tincstack/natlab:$(TAG)); WSF_TAG is exported for the scripts.
# RUN is the run id: every lab step of one `make` invocation writes into
# testing/{nat-sim,dpi-proof}/results/run/$(RUN)/ (git-ignored); the committed
# results/<date>/ trees are only touched by `make promote`.
# CI: .github/workflows/check.yml runs the same targets in the same order on
# every push/PR (lint, build-core, smoke, build-baseline, validate-nat,
# nat-quick, dpi-baseline), with TAG=ci and the core build cached in GHA.
TAG ?= ws-f
export WSF_TAG := $(TAG)
# LAB names the smoke lab: the compose project and its network ($(LAB)-smoke),
# its /24 and testing/smoke/run*. Two `make smoke LAB=...` runs with different
# LABs can share a host; the default keeps the historical `wsf-smoke` names.
LAB ?= wsf
RUN ?= $(shell date +%Y-%m-%d)-$(shell date +%H%M%S)
export WSF_RUN := $(RUN)
DATE ?= $(shell date +%Y-%m-%d)
export CORE_IMAGE := tincstack/core:$(TAG)
export BASELINE_IMAGE := tincstack/baseline:$(TAG)
SHELLCHECK_IMAGE ?= koalaman/shellcheck:stable
GITLEAKS_IMAGE ?= zricethezav/gitleaks:latest
# Every shell script here is linted at shellcheck's default (full) severity.
# The transport proofs used to be linted at -S warning because of pre-existing
# SC2086/SC2015 findings; those were cleaned up (stream U), so there is one
# list and one severity again.
SHELL_SCRIPTS := testing/baseline/build.sh testing/nat-sim/lab.sh testing/nat-sim/natlab.sh \
                 testing/nat-sim/natprofile.sh testing/dpi-proof/run.sh testing/dpi-proof/capture.sh \
                 testing/smoke/run.sh platforms/linux/docker/two-nodes.sh \
                 platforms/linux/docker/yaml-scripts.sh \
                 platforms/linux/docker/obfs-rekey-test.sh \
                 platforms/linux/docker/reload-test.sh \
                 testing/transports/singleflow-test.sh testing/transports/tls-front-test.sh \
                 testing/transports/https-carrier-test.sh testing/transports/quic-carrier-test.sh \
                 testing/transports/obfs-test.sh testing/transports/matrix-test.sh \
                 testing/transports/classify-test.sh \
                 testing/transports/plain-refuse-test.sh \
                 testing/transports/invitee-mesh-test.sh \
                 platforms/windows/build-core-win.sh platforms/windows/build-exe.sh \
                 platforms/windows/pyinstaller-in-wine.sh \
                 platforms/android/docker/emulator.sh \
                 platforms/android/docker/emulator-entrypoint.sh \
                 platforms/android/docker/join-on-emulator.sh \
                 platforms/android/docker/ui-join.sh

.PHONY: check build-core build-baseline build-lab smoke nat-quick nat-full laptop \
        validate-nat dpi-baseline lint secrets clean promote

check: build-core build-baseline smoke validate-nat nat-quick dpi-baseline
	@echo "make check: OK (run id $(RUN); lab results under testing/*/results/run/$(RUN)/)"

promote:
	testing/nat-sim/lab.sh promote testing/nat-sim/results/run/$(RUN) testing/nat-sim/results/$(DATE)
	testing/nat-sim/lab.sh promote testing/dpi-proof/results/run/$(RUN) testing/dpi-proof/results/$(DATE)

build-core:
	docker build -f core/Dockerfile.build -t $(CORE_IMAGE) core/
	docker run --rm $(CORE_IMAGE) tincd --version

build-baseline:
	testing/baseline/build.sh $(TAG)

build-lab: build-core build-baseline
	testing/nat-sim/lab.sh build

smoke: build-core
	LAB=$(LAB) testing/smoke/run.sh

validate-nat: build-lab
	testing/nat-sim/lab.sh validate-nat

nat-quick: build-lab
	testing/nat-sim/lab.sh matrix --quick --image core

nat-full: build-lab
	testing/nat-sim/lab.sh matrix --image both

laptop: build-lab
	testing/nat-sim/lab.sh laptop --image both

dpi-baseline: build-lab
	testing/dpi-proof/run.sh baseline

lint:
	docker run --rm -v "$(CURDIR):/mnt:ro" -w /mnt $(SHELLCHECK_IMAGE) -x $(SHELL_SCRIPTS)

# The repository is public: nothing key-shaped may enter it. .gitleaks.toml
# enumerates the placeholders and the one public upstream test vector that are
# allowed, so a genuinely new secret still fails this.
secrets:
	docker run --rm -v "$(CURDIR):/repo:ro" $(GITLEAKS_IMAGE) \
	    detect --source=/repo --config=/repo/.gitleaks.toml --no-banner --redact -v

clean:
	testing/nat-sim/lab.sh clean
	-docker compose -f testing/smoke/compose.yml down -v --remove-orphans
	rm -rf testing/smoke/run testing/smoke/run-*
