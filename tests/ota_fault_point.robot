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
${SUCCESS_IMAGE_HASH}          false
${SUCCESS_IMAGE_HASH_SLOT}     ${EMPTY}
${IMAGE_EXEC_SHA256}           ${EMPTY}
${IMAGE_STAGING_SHA256}        ${EMPTY}
${EXPECTED_EXEC_SHA256}        ${EMPTY}
${SUCCESS_OTADATA_EXPECT}      ${EMPTY}
${SUCCESS_OTADATA_EXPECT_SCOPE}    always
${STATE_PROBE_SCRIPT}          ${EMPTY}
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
    Execute Command    include "${ROOT}/peripherals/STM32DummyUSART.cs"
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
    Execute Command    $setup_script="${SETUP_SCRIPT}"
    Execute Command    $flash_backend="${FLASH_BACKEND}"
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
    Execute Command    $success_image_hash="${SUCCESS_IMAGE_HASH}"
    Execute Command    $success_image_hash_slot="${SUCCESS_IMAGE_HASH_SLOT}"
    Execute Command    $image_exec_sha256="${IMAGE_EXEC_SHA256}"
    Execute Command    $image_staging_sha256="${IMAGE_STAGING_SHA256}"
    Execute Command    $expected_exec_sha256="${EXPECTED_EXEC_SHA256}"
    Execute Command    $success_otadata_expect="${SUCCESS_OTADATA_EXPECT}"
    Execute Command    $success_otadata_expect_scope="${SUCCESS_OTADATA_EXPECT_SCOPE}"
    Execute Command    $state_probe_script="${STATE_PROBE_SCRIPT}"
    Execute Command    $hash_bypass_symbols="${HASH_BYPASS_SYMBOLS}"
    Execute Command    $progress_stall_timeout_s="${PROGRESS_STALL_TIMEOUT_S}"
    Execute Command    $expect_control_outcome="${EXPECT_CONTROL_OUTCOME}"
    Execute Command    $postmortem_dump_no_boot="${POSTMORTEM_DUMP_NO_BOOT}"
    Execute Command    $postmortem_dump_header_bytes="${POSTMORTEM_DUMP_HEADER_BYTES}"
    Execute Command    $resume_trace_no_boot="${RESUME_TRACE_NO_BOOT}"
    Execute Command    $resume_trace_max_ops="${RESUME_TRACE_MAX_OPS}"
    Execute Command    $resume_trace_time_slice="${RESUME_TRACE_TIME_SLICE}"
    Execute Command    $resume_trace_wall_timeout_s="${RESUME_TRACE_WALL_TIMEOUT_S}"

    Execute Script    ${ROOT}/scripts/run_runtime_fault_sweep.resc

    File Should Exist    ${RESULT_FILE}

*** Test Cases ***
Run OTA Fault Point
    [Timeout]    ${TEST_TIMEOUT}
    Run Runtime Fault Point
