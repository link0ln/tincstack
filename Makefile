# tincstack — verification entry points (M9). Everything runs in Docker;
# nothing is installed on the host. `make check` is the one CI command.
#
#   make check          build core + baseline images, two-node YAML smoke test,
#                       NAT lab quick subset (core), dpi-proof baseline capture
#   make nat-full       the whole NAT matrix, core and baseline (~40 min)
#   make laptop         the CGNAT / sleep-resume regression, core vs baseline
#   make dpi-baseline   capture plain tinc and assert its fingerprints
#   make lint           shellcheck every shell script (in a container)
#
# TAG selects the image tag family (tincstack/core:$(TAG), tincstack/baseline:$(TAG),
# tincstack/natlab:$(TAG)); WSF_TAG is exported for the scripts.
TAG ?= ws-f
export WSF_TAG := $(TAG)
export CORE_IMAGE := tincstack/core:$(TAG)
export BASELINE_IMAGE := tincstack/baseline:$(TAG)
SHELLCHECK_IMAGE ?= koalaman/shellcheck:stable
SHELL_SCRIPTS := testing/baseline/build.sh testing/nat-sim/lab.sh testing/nat-sim/natlab.sh \
                 testing/nat-sim/natprofile.sh testing/dpi-proof/run.sh testing/dpi-proof/capture.sh \
                 testing/smoke/run.sh

.PHONY: check build-core build-baseline build-lab smoke nat-quick nat-full laptop \
        validate-nat dpi-baseline lint clean

check: build-core build-baseline smoke validate-nat nat-quick dpi-baseline
	@echo "make check: OK"

build-core:
	docker build -f core/Dockerfile.build -t $(CORE_IMAGE) core/
	docker run --rm $(CORE_IMAGE) tincd --version

build-baseline:
	testing/baseline/build.sh $(TAG)

build-lab: build-core build-baseline
	testing/nat-sim/lab.sh build

smoke: build-core
	testing/smoke/run.sh

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

clean:
	testing/nat-sim/lab.sh clean
	-docker compose -f testing/smoke/compose.yml down -v --remove-orphans
	rm -rf testing/smoke/run
