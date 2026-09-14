.PHONY: bootstrap build native-build conformance-build auth-keys verify unit smoke reproduce-smoke test native-exhaustive native-fault native-loss-smoke native-handoff full-cycle-smoke full-cycle-smoke-quick full-cycle-compare exhaustive sanitize demo benchmark ablation conformance-ablation package package-evidence package-complete clean

TPC := vendor/paraswap/two-party computation
BUILD := $(TPC)/build-full

bootstrap:
	bash scripts/bootstrap_native_dependencies.sh

build: native-build conformance-build

native-build:
	cmake -S "$(TPC)" -B "$(BUILD)"
	cmake --build "$(BUILD)" -j $${BUILD_JOBS:-2}

conformance-build:
	$(MAKE) -C vendor/oasis-linear -j $${BUILD_JOBS:-2}

auth-keys: native-build
	bash scripts/prepare_curve_credentials.sh "$${AUTH_DIR:-auth/generated}"

verify:
	python3 scripts/verify_upstream.py
	python3 scripts/verify_oasis_core.py

unit:
	python3 -m unittest discover -s tests -v

smoke: native-build
	bash scripts/run_local_smoke.sh

# Fresh Ubuntu entry point: install pinned dependencies, then run the complete
# local correctness and two-role runner gate.
reproduce-smoke: bootstrap smoke

test:
	bash scripts/run_integration_tests.sh

# Publication differential campaign for the native C11/RELIC implementation.
native-exhaustive: native-build
	python3 scripts/run_native_differential_campaign.py \
		--vectors 100000 --out results/native-differential-100000.json

native-fault: native-build
	python3 scripts/run_native_fault_campaign.py \
		--trials 100 --warmup 10 --out results/native-fault-final.json

native-loss-smoke: native-build
	python3 scripts/test_native_loss_runner.py

native-handoff: native-build
	python3 scripts/run_native_handoff.py --participants $${PARTICIPANTS:-3} \
		--negative-tests --output "$${HANDOFF_OUT:-results/native-handoff.json}"

# Retained local lifecycle integration gates. These use the same coordinator
# for baseline and OASIS; participant custody is still the centralized fixture.
full-cycle-smoke: native-build
	python3 scripts/test_retained_full_cycle.py --participants $${PARTICIPANTS:-3}

.PHONY: retained-abort-test
retained-abort-test: native-build
	python3 scripts/test_retained_abort.py

full-cycle-smoke-quick: native-build
	python3 scripts/test_retained_full_cycle.py --participants $${PARTICIPANTS:-3} --quick

full-cycle-compare: native-build
	python3 scripts/compare_full_cycle_modes.py --participants $${PARTICIPANTS:-3} \
		--repetitions $${REPETITIONS:-1} $${OUTCOME:---all-honest} \
		> "$${FULL_CYCLE_OUT:-results/retained-full-cycle-comparison.json}"

# Secondary C++/OpenSSL conformance campaign; not primary native evidence.
exhaustive: conformance-build
	python3 scripts/run_differential_campaign.py \
		--binary vendor/oasis-linear/bin/oasis_transport \
		--vectors 100000 --out results/conformance-100000.json

sanitize:
	$(MAKE) -C vendor/oasis-linear sanitize

demo: build
	python3 src/paraswap_lifecycle.py --participants 3 --mode batch-joint-presigning-batch-verification \
		--output results/demo.json

benchmark: build
	python3 scripts/run_local_ablation.py --participants 3,5,8 --trials 10 \
			--output results/preswap-lifecycle-benchmark.json

ablation: native-build
	python3 scripts/run_local_ablation.py --participants 3,5,8,16 --trials 10 \
			--output results/preswap-ablation.json

conformance-ablation: conformance-build
	python3 scripts/run_conformance_ablation.py --participants 5,8,16 --trials 10 \
			--output results/conformance-ablation.json

.PHONY: native-vtd-setup-test
native-vtd-setup-test: native-build
	"$(TPC)/bin/vtd_setup_test"

.PHONY: native-vtd-integration-test
native-vtd-integration-test: native-build
	"$(TPC)/bin/vtd_integration_test"

package:
	bash scripts/package_source_release.sh

package-evidence:
	bash scripts/package_cloud_evidence.sh

package-complete:
	bash scripts/package_complete_artifact.sh

clean:
	rm -f results/*.json /tmp/oasis-preswap-*.sock
	rm -rf results/runtime-keys "$(BUILD)" "$(TPC)/bin" \
		vendor/oasis-linear/build vendor/oasis-linear/bin
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
