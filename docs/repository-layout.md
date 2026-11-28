# Repository layout and CI workflows

Where things live in the repository and which workflows run.

## CI workflows

| Workflow                              | Trigger                  | What it does                          |
| ------------------------------------- | ------------------------ | ------------------------------------- |
| `ci.yml`                              | push, PR                 | License gate, Robot/pytest, self-test |
| `profile-sweep.yml`                   | workflow_dispatch        | On-demand single-profile sweep        |
| `action-validation.yml`               | push, PR                 | Validates the reusable GitHub Action  |
| `oss-validation.yml`                  | path-filtered push to `main`, schedule, dispatch | OSS validation guards |
| `mcuboot-head-exploratory.yml`        | workflow_dispatch        | MCUboot exploratory scenario          |
| `mcuboot-head-zero-day.yml`           | schedule, dispatch       | MCUboot HEAD zero-day fault sweeps    |
| `nuttx-nxboot-real-exploratory.yml`   | workflow_dispatch        | Real NuttX nxboot exploratory sweep   |
| `nuttx-nxboot-revert-canary.yml`      | schedule, dispatch       | NuttX revert property canary          |
| `nuttx-nxboot-multi-fault-canary.yml` | schedule, dispatch       | NuttX nxboot multi-fault sweep canary |
| `renode-latest-canary.yml`            | schedule, dispatch       | Tests against latest Renode build     |

See [`docs/zero-day-results.md`](zero-day-results.md) for the zero-day sweep results across all six profiles in `mcuboot-head-zero-day.yml`.

## Repository layout

```text
tardigrade/
├── action.yml                        # Reusable GitHub Action
├── scripts/
│   ├── audit_bootloader.py           # Primary CLI entry point
│   ├── run_scenario.py               # Multi-step scenario runner
│   ├── profile_loader.py             # YAML profile parser + validation
│   ├── invariants.py                 # 20 named postcondition invariants
│   ├── self_test.py                  # Self-test across known defect corpus
│   ├── run_runtime_fault_sweep.resc  # Renode fault sweep engine
│   ├── write_trace_heuristic.py      # Write-trace classification
│   ├── writeback_reconstruction.py   # Durable snapshot reconstruction
│   ├── authenticated_equivalence.py  # Authenticated-content equivalence campaign
│   ├── preauth_bounds_oracle.py     # Synthetic pre-auth bounds oracle
│   ├── boot_cycle_analysis.py        # Multi-boot convergence analysis
│   ├── fault_inject.py               # Fault injection helpers
│   ├── partial_staging.py            # Partial staging-image simulation
│   ├── render_results_html.py        # HTML report renderer
│   ├── boundary_campaigns.py         # Security-counter boundary expansion
│   ├── security_state_layout.py      # Persistent erase-domain analysis
│   ├── terminal_error_escape.py      # Emitted-ELF terminal-path analysis
│   ├── update_protocol_analyzer.py   # Update gate/content-binding analysis
│   ├── authorization_review_analyzer.py # Reviewed-versus-signed analysis
│   ├── production_assert_analyzer.py # Optimized-build assertion review
│   ├── cbmc_to_profile.py            # CBMC counterexample converter
│   ├── fuzz_crash_to_profile.py      # Fuzzer crash-to-profile converter
│   ├── fuzz_to_profile.py            # Legacy fuzzer bridge
│   ├── run_oss_validation.py         # OSS validation runner
│   └── license_certify.py            # Strict source-release license gate
├── targets/
│   ├── esp_idf/                      # ESP-IDF model probe + invariants
│   ├── mcuboot/                      # MCUboot probe, invariants, state fuzzer
│   ├── nuttx_nxboot/                 # Real NuttX build + runtime profile gen
│   ├── nxboot/                       # Shared nxboot-style probe + invariants
│   ├── rustboot/                     # rustBoot probe + invariants
│   └── tf_m_bl2/                     # TF-M multi-image probe + evaluator
├── profiles/                         # YAML audit profiles (~180 profiles)
├── scenarios/                        # Multi-step scenario definitions
├── examples/                         # Reference firmware, models, and trace fixtures
├── harnesses/                        # Fuzzer harness templates
├── peripherals/                      # Renode C# peripherals with fault hooks
│   ├── NRF52NVMC.cs                  #   NVMC flash with write/erase faults
│   ├── NVMemoryController.cs         #   NVMemory slow-path backend
│   ├── GenericNvmController.cs       #   Command-register NVM controller
│   ├── I2CFaultProxy.cs              #   I2C bus fault injection proxy
│   ├── OTPMemory.cs                  #   OTP fuse-blow fault model
│   ├── STM32F4FlashController.cs     #   STM32F4 flash controller
│   ├── STM32H7FlashController.cs     #   STM32H7 flash controller
│   ├── An521NvmInterceptor.cs        #   AN521 RAM-backed NVM interception
│   ├── CMSDKAPBWatchdog.cs           #   CMSDK watchdog model
│   ├── Sse200MpcStub.cs              #   SSE-200 MPC register model
│   ├── TraceReplayEngine.cs          #   Trace replay for fast Phase 1
│   └── FaultTracker.cs               #   Shared fault-tracking + writeback overlay
├── platforms/                        # Renode platform definitions (.repl)
├── tests/                            # Robot Framework + pytest suites
├── docker/                           # Dockerfiles for CI
├── results/oss_validation/assets/    # Pre-built MCUboot ELFs + slot images
└── docs/
    ├── writing-profiles.md           # Profile-writing guide + result interpretation
    ├── authenticated-equivalence.md  # Authenticated-content campaign guide
    ├── preauth-bounds-oracle.md      # Synthetic pre-auth bounds guide
    ├── license-certification.md      # Strict source-package license boundary
    ├── rustboot-target.md            # rustBoot adapter reference
    ├── i2c-fault-model.md            # I2C fault injection model
    └── otp-backend.md                # OTP fuse-blow backend
```
