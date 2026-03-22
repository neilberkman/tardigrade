*** Settings ***
Library    OperatingSystem

*** Variables ***
${ROOT}                        ${CURDIR}/..
${FAULT_AT}                    0
${RESULT_FILE}                 /tmp/ota_fault_point.json
${PLATFORM_REPL}               ${ROOT}/platforms/cortex_m0_nvm.repl
${RUNTIME_MODE}                true
${CALIBRATION_MODE}            false
${EVALUATION_MODE}             execute
${BOOTLOADER_ELF}              ${ROOT}/examples/vulnerable_ota/firmware.elf
${BOOTLOADER_ENTRY}            0x10000000
${SRAM_START}                  0x20000000
${SRAM_END}                    0x20020000
${WRITE_GRANULARITY}           8
${RUN_DURATION}                0.005
${MAX_STEP_LIMIT}              100000
${MAX_WRITES_CAP}              512
${SLOT_EXEC_BASE}              0x10000000
${SLOT_EXEC_SIZE}              0x38000
${SLOT_STAGING_BASE}           0x10038000
${SLOT_STAGING_SIZE}           0x38000
${SLOT_TERTIARY_BASE}          ${EMPTY}
${SLOT_TERTIARY_SIZE}          ${EMPTY}
${SLOT_RECOVERY_BASE}          ${EMPTY}
${SLOT_RECOVERY_SIZE}          ${EMPTY}
${IMAGE_EXEC}                  ${EMPTY}
${IMAGE_STAGING}               ${ROOT}/examples/vulnerable_ota/firmware.bin
${IMAGE_TERTIARY}              ${EMPTY}
${IMAGE_RECOVERY}              ${EMPTY}
${PRE_BOOT_STATE_BIN}          ${EMPTY}
${UPDATE_SEQUENCE_FILE}        ${EMPTY}
${SETUP_SCRIPT}                ${EMPTY}
${SUCCESS_VTOR_SLOT}           exec
${SUCCESS_VECTOR_OFFSET}       0
${SUCCESS_PC_SLOT}             ${EMPTY}
${SUCCESS_MARKER_ADDR}         0
${SUCCESS_MARKER_VALUE}        0
${FAULT_POINTS_CSV}            ${EMPTY}
${IMAGE_STAGING_PATH}          ${ROOT}/examples/vulnerable_ota/firmware.bin
${IMAGE_EXEC_PATH}             ${EMPTY}
${IMAGE_TERTIARY_PATH}         ${EMPTY}
${IMAGE_RECOVERY_PATH}         ${EMPTY}
${TRACE_FILE}                  ${EMPTY}
${ERASE_TRACE_FILE}            ${EMPTY}
${TRACE_FILE_BIN}              ${EMPTY}
${ERASE_TRACE_FILE_BIN}        ${EMPTY}
${FAULT_TYPES}                 write
${FAULT_TYPE_CSV}              ${EMPTY}
${BOOT_CYCLES}                 1
${CALIBRATION_TIME_SLICE}      ${EMPTY}
${PHASE1_TIME_SLICE}           ${EMPTY}
${PHASE2_TIME_SLICE}           ${EMPTY}
${BOOT_CYCLE_HOOK}            ${EMPTY}
${EXPECTED_ROLLBACK_AT_CYCLE}    ${EMPTY}
${SUCCESS_IMAGE_HASH}          false
${SUCCESS_IMAGE_HASH_SLOT}     ${EMPTY}
${IMAGE_EXEC_SHA256}           ${EMPTY}
${IMAGE_STAGING_SHA256}        ${EMPTY}
${EXPECTED_EXEC_SHA256}        ${EMPTY}
${SUCCESS_OTADATA_EXPECT}      ${EMPTY}
${SUCCESS_OTADATA_EXPECT_SCOPE}    always
${SECURITY_ANTI_ROLLBACK}      false
${STATE_PROBE}                 ${EMPTY}
${HASH_BYPASS_SYMBOLS}         ${EMPTY}
${PROGRESS_STALL_TIMEOUT_S}    5
${EXPECT_CONTROL_OUTCOME}      ${EMPTY}
${POSTMORTEM_DUMP_NO_BOOT}     true
${POSTMORTEM_DUMP_HEADER_BYTES}    4096
${RESUME_TRACE_NO_BOOT}        true
${RESUME_TRACE_MAX_OPS}        1024
${RESUME_TRACE_TIME_SLICE}     0.02
${RESUME_TRACE_WALL_TIMEOUT_S}    30
${EXTRA_PERIPHERALS}           ${EMPTY}
${FLASH_BACKEND}               ${EMPTY}
${NVM_CONTROLLER}              ${EMPTY}
${BOOT_REGISTER_PRE_WRITES}    ${EMPTY}
${BOOT_REGISTERS}              ${EMPTY}
${RESET_MODE}                  warm
${ENABLE_MACHINE_SNAPSHOTS}    false
${PHASE2_FAULT_ENABLED}        false
${PHASE2_FAULT_MAX_POINTS}     0
${SUCCESS_CRITERIA_OVERRIDES}    ${EMPTY}
${SUCCESS_CRITERIA_OVERRIDES_FILE}    ${EMPTY}
${OTP_PERIPHERAL}              ${EMPTY}
${NVS_REGION_ADDR}             ${EMPTY}
${NVS_REGION_SIZE}             ${EMPTY}
${NVS_REGION_SNAPSHOT}         ${EMPTY}
${NVS_CORRUPTION_MODES}        ${EMPTY}
${NVS_CORRUPTION_SEED}         0
${I2C_FAULT_PERIPHERAL}        ${EMPTY}
${INSTRUCTION_SKIP_REGIONS}    ${EMPTY}
${INSTRUCTION_SKIP_COUNT}      1
${VERIFICATION_PROBES}         ${EMPTY}
${READ_FAULT_REGIONS}          ${EMPTY}
${READ_FAULT_BIT_FLIPS}        0
${READ_FAULT_PROBABILITY}      1.0
${READ_FAULT_SEED}             0
${DURABILITY_MODEL}            direct
${WRITEBACK_BUFFER_CAPACITY}   auto
${WRITEBACK_BARRIERS}          ${EMPTY}
${WRITEBACK_ERASE_FLUSHES}     false
${TEST_TIMEOUT}                2 minutes

*** Keywords ***
Load Runtime Scenario
    [Documentation]    Profile-driven runtime scenario: load peripheral, platform, ELF, and seed images.
    Execute Command    include "${ROOT}/peripherals/NVMemoryController.cs"
    Execute Command    include "${ROOT}/peripherals/GenericNvmController.cs"
    Execute Command    include "${ROOT}/peripherals/ITardigradeFaultInjectable.cs"
    Execute Command    include "${ROOT}/peripherals/FaultTracker.cs"
    Execute Command    include "${ROOT}/peripherals/NRF52NVMC.cs"
    Execute Command    include "${ROOT}/peripherals/NRF52UARTE.cs"
    Execute Command    include "${ROOT}/peripherals/SimpleCacheController.cs"
    Execute Command    include "${ROOT}/peripherals/TraceReplayEngine.cs"
    Execute Command    include "${ROOT}/peripherals/STM32F4FlashController.cs"
    Execute Command    include "${ROOT}/peripherals/STM32F4FlashInterceptor.cs"
    Execute Command    include "${ROOT}/peripherals/STM32F4FastFlash.cs"
    Execute Command    include "${ROOT}/peripherals/STM32F4RCCStub.cs"
    Execute Command    include "${ROOT}/peripherals/STM32H7FlashController.cs"
    Execute Command    include "${ROOT}/peripherals/STM32H7RCCStub.cs"
    Execute Command    include "${ROOT}/peripherals/STM32H7PWRStub.cs"
    Execute Command    include "${ROOT}/peripherals/STM32DummyUSART.cs"
    Execute Command    include "${ROOT}/peripherals/OTPMemory.cs"
    Execute Command    include "${ROOT}/peripherals/I2CFaultProxy.cs"
    Run Keyword If    '${EXTRA_PERIPHERALS}' != ''    Load Extra Peripherals
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${PLATFORM_REPL}
    ${load_cmds}=    Set Variable    bus=monitor.Machine.SystemBus; bus.LoadELF(r'${BOOTLOADER_ELF}')
    Run Keyword If    '${IMAGE_EXEC}' != ''    Execute Command    python "bus=monitor.Machine.SystemBus; bus.LoadBinary(r'${IMAGE_EXEC}', ${SLOT_EXEC_BASE})"
    Run Keyword If    '${IMAGE_STAGING}' != ''    Execute Command    python "bus=monitor.Machine.SystemBus; bus.LoadBinary(r'${IMAGE_STAGING}', ${SLOT_STAGING_BASE})"
    Run Keyword If    '${IMAGE_TERTIARY}' != '' and '${SLOT_TERTIARY_BASE}' != ''    Execute Command    python "bus=monitor.Machine.SystemBus; bus.LoadBinary(r'${IMAGE_TERTIARY}', ${SLOT_TERTIARY_BASE})"
    Run Keyword If    '${IMAGE_RECOVERY}' != '' and '${SLOT_RECOVERY_BASE}' != ''    Execute Command    python "bus=monitor.Machine.SystemBus; bus.LoadBinary(r'${IMAGE_RECOVERY}', ${SLOT_RECOVERY_BASE})"
    Execute Command    python "${load_cmds}"

Load Extra Peripherals
    [Documentation]    Compile additional C# peripherals specified as comma-separated paths.
    @{paths}=    Split String    ${EXTRA_PERIPHERALS}    ,
    FOR    ${path}    IN    @{paths}
        Execute Command    include "${path}"
    END

Run Runtime Fault Point
    [Documentation]    Profile-driven runtime fault sweep. Uses run_runtime_fault_sweep.resc.
    Load Runtime Scenario

    Execute Command    $repo_root="${ROOT}"
    Execute Command    $fault_at=${FAULT_AT}
    Execute Command    $result_file="${RESULT_FILE}"
    Execute Command    $calibration_mode=${CALIBRATION_MODE}
    Execute Command    $evaluation_mode="${EVALUATION_MODE}"
    Execute Command    $run_duration="${RUN_DURATION}"
    Execute Command    $max_step_limit=${MAX_STEP_LIMIT}
    Execute Command    $max_writes_cap=${MAX_WRITES_CAP}
    Execute Command    $bootloader_elf="${BOOTLOADER_ELF}"
    Execute Command    $bootloader_entry=${BOOTLOADER_ENTRY}
    Execute Command    $sram_start=${SRAM_START}
    Execute Command    $sram_end=${SRAM_END}
    Execute Command    $slot_exec_base=${SLOT_EXEC_BASE}
    Execute Command    $slot_exec_size=${SLOT_EXEC_SIZE}
    Execute Command    $slot_staging_base=${SLOT_STAGING_BASE}
    Execute Command    $slot_staging_size=${SLOT_STAGING_SIZE}
    Run Keyword If    '${SLOT_TERTIARY_BASE}' != ''    Execute Command    $slot_tertiary_base=${SLOT_TERTIARY_BASE}
    Run Keyword If    '${SLOT_TERTIARY_SIZE}' != ''    Execute Command    $slot_tertiary_size=${SLOT_TERTIARY_SIZE}
    Run Keyword If    '${SLOT_RECOVERY_BASE}' != ''    Execute Command    $slot_recovery_base=${SLOT_RECOVERY_BASE}
    Run Keyword If    '${SLOT_RECOVERY_SIZE}' != ''    Execute Command    $slot_recovery_size=${SLOT_RECOVERY_SIZE}
    Execute Command    $pre_boot_state_bin="${PRE_BOOT_STATE_BIN}"
    Run Keyword If    '${UPDATE_SEQUENCE_FILE}' != ''    Execute Command    $update_sequence_file="${UPDATE_SEQUENCE_FILE}"
    Execute Command    $setup_script="${SETUP_SCRIPT}"
    Execute Command    $flash_backend="${FLASH_BACKEND}"
    Run Keyword If    '${NVM_CONTROLLER}' != ''    Execute Command    $nvm_controller="${NVM_CONTROLLER}"
    Execute Command    $enable_machine_snapshots="${ENABLE_MACHINE_SNAPSHOTS}"
    Execute Command    $success_vtor_slot="${SUCCESS_VTOR_SLOT}"
    Execute Command    $success_vector_offset=${SUCCESS_VECTOR_OFFSET}
    Execute Command    $success_pc_slot="${SUCCESS_PC_SLOT}"
    Execute Command    $success_marker_addr=${SUCCESS_MARKER_ADDR}
    Execute Command    $success_marker_value=${SUCCESS_MARKER_VALUE}
    Execute Command    $fault_points_csv="${FAULT_POINTS_CSV}"
    Execute Command    $image_staging_path="${IMAGE_STAGING_PATH}"
    Execute Command    $image_exec_path="${IMAGE_EXEC_PATH}"
    Run Keyword If    '${IMAGE_TERTIARY_PATH}' != ''    Execute Command    $image_tertiary_path="${IMAGE_TERTIARY_PATH}"
    Run Keyword If    '${IMAGE_RECOVERY_PATH}' != ''    Execute Command    $image_recovery_path="${IMAGE_RECOVERY_PATH}"
    Execute Command    $trace_file="${TRACE_FILE}"
    Execute Command    $erase_trace_file="${ERASE_TRACE_FILE}"
    Execute Command    $trace_file_bin="${TRACE_FILE_BIN}"
    Execute Command    $erase_trace_file_bin="${ERASE_TRACE_FILE_BIN}"
    Execute Command    $fault_types="${FAULT_TYPES}"
    Execute Command    $fault_type_csv="${FAULT_TYPE_CSV}"
    Execute Command    $boot_cycles="${BOOT_CYCLES}"
    Run Keyword If    '${CALIBRATION_TIME_SLICE}' != ''    Execute Command    $calibration_time_slice="${CALIBRATION_TIME_SLICE}"
    Run Keyword If    '${PHASE1_TIME_SLICE}' != ''    Execute Command    $phase1_time_slice="${PHASE1_TIME_SLICE}"
    Run Keyword If    '${PHASE2_TIME_SLICE}' != ''    Execute Command    $phase2_time_slice="${PHASE2_TIME_SLICE}"
    Run Keyword If    '${BOOT_CYCLE_HOOK}' != ''    Execute Command    $boot_cycle_hook="${BOOT_CYCLE_HOOK}"
    Run Keyword If    '${EXPECTED_ROLLBACK_AT_CYCLE}' != ''    Execute Command    $expected_rollback_at_cycle=${EXPECTED_ROLLBACK_AT_CYCLE}
    Execute Command    $success_image_hash="${SUCCESS_IMAGE_HASH}"
    Execute Command    $success_image_hash_slot="${SUCCESS_IMAGE_HASH_SLOT}"
    Execute Command    $image_exec_sha256="${IMAGE_EXEC_SHA256}"
    Execute Command    $image_staging_sha256="${IMAGE_STAGING_SHA256}"
    Execute Command    $expected_exec_sha256="${EXPECTED_EXEC_SHA256}"
    Execute Command    $success_otadata_expect="${SUCCESS_OTADATA_EXPECT}"
    Execute Command    $success_otadata_expect_scope="${SUCCESS_OTADATA_EXPECT_SCOPE}"
    Execute Command    $security_anti_rollback="${SECURITY_ANTI_ROLLBACK}"
    Execute Command    $state_probe="${STATE_PROBE}"
    Execute Command    $hash_bypass_symbols="${HASH_BYPASS_SYMBOLS}"
    Execute Command    $progress_stall_timeout_s="${PROGRESS_STALL_TIMEOUT_S}"
    Execute Command    $expect_control_outcome="${EXPECT_CONTROL_OUTCOME}"
    Execute Command    $postmortem_dump_no_boot="${POSTMORTEM_DUMP_NO_BOOT}"
    Execute Command    $postmortem_dump_header_bytes="${POSTMORTEM_DUMP_HEADER_BYTES}"
    Execute Command    $resume_trace_no_boot="${RESUME_TRACE_NO_BOOT}"
    Execute Command    $resume_trace_max_ops="${RESUME_TRACE_MAX_OPS}"
    Execute Command    $resume_trace_time_slice="${RESUME_TRACE_TIME_SLICE}"
    Execute Command    $resume_trace_wall_timeout_s="${RESUME_TRACE_WALL_TIMEOUT_S}"
    Run Keyword If    '${SUCCESS_CRITERIA_OVERRIDES}' != ''    Execute Command    $success_criteria_overrides="${SUCCESS_CRITERIA_OVERRIDES}"
    Run Keyword If    '${SUCCESS_CRITERIA_OVERRIDES_FILE}' != ''    Execute Command    $success_criteria_overrides_file="${SUCCESS_CRITERIA_OVERRIDES_FILE}"
    Run Keyword If    '${BOOT_REGISTER_PRE_WRITES}' != ''    Execute Command    $boot_register_pre_writes="${BOOT_REGISTER_PRE_WRITES}"
    Run Keyword If    '${BOOT_REGISTERS}' != ''    Execute Command    $boot_registers="${BOOT_REGISTERS}"
    Execute Command    $reset_mode="${RESET_MODE}"
    Run Keyword If    '${OTP_PERIPHERAL}' != ''    Execute Command    $otp_peripheral="${OTP_PERIPHERAL}"
    Run Keyword If    '${NVS_REGION_ADDR}' != ''    Execute Command    $nvs_region_addr="${NVS_REGION_ADDR}"
    Run Keyword If    '${NVS_REGION_SIZE}' != ''    Execute Command    $nvs_region_size="${NVS_REGION_SIZE}"
    Run Keyword If    '${NVS_REGION_SNAPSHOT}' != ''    Execute Command    $nvs_region_snapshot="${NVS_REGION_SNAPSHOT}"
    Run Keyword If    '${NVS_CORRUPTION_MODES}' != ''    Execute Command    $nvs_corruption_modes="${NVS_CORRUPTION_MODES}"
    Run Keyword If    '${NVS_CORRUPTION_SEED}' != '0'    Execute Command    $nvs_corruption_seed="${NVS_CORRUPTION_SEED}"
    Run Keyword If    '${I2C_FAULT_PERIPHERAL}' != ''    Execute Command    $i2c_fault_peripheral="${I2C_FAULT_PERIPHERAL}"
    Run Keyword If    '${INSTRUCTION_SKIP_REGIONS}' != ''    Execute Command    $instruction_skip_regions="${INSTRUCTION_SKIP_REGIONS}"
    Run Keyword If    '${INSTRUCTION_SKIP_COUNT}' != '1'    Execute Command    $instruction_skip_count="${INSTRUCTION_SKIP_COUNT}"
    Run Keyword If    '${VERIFICATION_PROBES}' != ''    Execute Command    $verification_probes="${VERIFICATION_PROBES}"
    Run Keyword If    '${READ_FAULT_REGIONS}' != ''    Execute Command    $read_fault_regions="${READ_FAULT_REGIONS}"
    Run Keyword If    '${READ_FAULT_BIT_FLIPS}' != '0'    Execute Command    $read_fault_bit_flips="${READ_FAULT_BIT_FLIPS}"
    Run Keyword If    '${READ_FAULT_PROBABILITY}' != '1.0'    Execute Command    $read_fault_probability="${READ_FAULT_PROBABILITY}"
    Run Keyword If    '${READ_FAULT_SEED}' != '0'    Execute Command    $read_fault_seed="${READ_FAULT_SEED}"
    Execute Command    $durability_model="${DURABILITY_MODEL}"
    Execute Command    $writeback_buffer_capacity="${WRITEBACK_BUFFER_CAPACITY}"
    Execute Command    $writeback_barriers="${WRITEBACK_BARRIERS}"
    Execute Command    $writeback_erase_flushes="${WRITEBACK_ERASE_FLUSHES}"

    Execute Script    ${ROOT}/scripts/run_runtime_fault_sweep.resc

    File Should Exist    ${RESULT_FILE}

*** Test Cases ***
Run OTA Fault Point
    [Timeout]    ${TEST_TIMEOUT}
    Run Runtime Fault Point
