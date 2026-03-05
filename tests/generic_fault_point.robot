*** Settings ***
Library    OperatingSystem
Library    String
Library    Collections

*** Variables ***
${ROOT}                        ${CURDIR}/..
${REPORT_SCENARIO}             external
${FAULT_AT}                    0
${TOTAL_WRITES}                28672
${RESULT_FILE}                 /tmp/generic_fault_result.json
${PLATFORM_REPL}               ${ROOT}/platforms/cortex_m0_nvm.repl
${FIRMWARE_ELF}                ${EMPTY}
${BOOTLOADER_ELF}              ${EMPTY}
${BOOT_META_BIN}               ${EMPTY}
${META_BASE}                   0x10070000
${FAULT_POINT_SCRIPT}          ${ROOT}/scripts/run_copy_in_place_fault_point.resc
${PERIPHERAL_INCLUDES}         ${EMPTY}
${INCLUDE_METADATA_FAULTS}     false
${EVALUATION_MODE}             execute
${BOOT_MODE}                   ${EMPTY}
${SLOT_A_IMAGE_FILE}           ${EMPTY}
${SLOT_B_IMAGE_FILE}           ${EMPTY}
${OTA_HEADER_SIZE}             ${EMPTY}

# Optional pass-through monitor variables for generic scripts.
${WRITE_GRANULARITY}           ${EMPTY}
${ACTIVE_BASE}                 ${EMPTY}
${STAGING_BASE}                ${EMPTY}
${NVM_CTRL_PATH}               ${EMPTY}
${SLOT_A_BASE}                 ${EMPTY}
${SLOT_B_BASE}                 ${EMPTY}
${SLOT_SIZE}                   ${EMPTY}
${META_BASE_0}                 ${EMPTY}
${META_BASE_1}                 ${EMPTY}
${META_SIZE}                   ${EMPTY}
${BOOTLOADER_ENTRY}            ${EMPTY}
${RUN_DURATION}                ${EMPTY}
${TRACE_EXECUTION}             false
${TRACE_FILE}                  ${EMPTY}

*** Keywords ***
Resolve Path
    [Arguments]    ${path_value}
    ${is_abs}=    Evaluate    os.path.isabs(r'''${path_value}''')    modules=os
    ${resolved}=    Run Keyword If    ${is_abs}
    ...    Set Variable    ${path_value}
    ...    ELSE    Normalize Path    ${ROOT}/${path_value}
    [Return]    ${resolved}

Include Peripheral If Provided
    [Arguments]    ${cs_path}
    ${trimmed}=    Strip String    ${cs_path}
    Run Keyword If    '${trimmed}' == ''    Return From Keyword
    ${resolved_cs}=    Resolve Path    ${trimmed}
    Execute Command    include "${resolved_cs}"

Load ELF If Provided
    [Arguments]    ${elf_path}
    Run Keyword If    '${elf_path}' == '${EMPTY}'    Return From Keyword
    ${resolved_elf}=    Resolve Path    ${elf_path}
    Execute Command    sysbus LoadELF @${resolved_elf}

Load Binary If Provided
    [Arguments]    ${bin_path}    ${address}
    Run Keyword If    '${bin_path}' == '${EMPTY}'    Return From Keyword
    ${resolved_bin}=    Resolve Path    ${bin_path}
    Execute Command    sysbus LoadBinary @${resolved_bin} ${address}

Load Generic Firmware
    Execute Command    include "${ROOT}/peripherals/NVMemoryController.cs"
    Execute Command    include "${ROOT}/peripherals/GenericNvmController.cs"
    Execute Command    include "${ROOT}/peripherals/TraceReplayEngine.cs"

    @{includes}=    Run Keyword If    '${PERIPHERAL_INCLUDES}' != '${EMPTY}'
    ...    Split String    ${PERIPHERAL_INCLUDES}    ;
    ...    ELSE    Create List
    FOR    ${cs_file}    IN    @{includes}
        Include Peripheral If Provided    ${cs_file}
    END

    ${resolved_platform}=    Resolve Path    ${PLATFORM_REPL}
    Execute Command    mach create
    Execute Command    machine LoadPlatformDescription @${resolved_platform}

    Load ELF If Provided    ${FIRMWARE_ELF}

    Load Binary If Provided    ${BOOT_META_BIN}    ${META_BASE}

    # Load bootloader last in case firmware ELF LOAD segments include low-vector regions.
    Load ELF If Provided    ${BOOTLOADER_ELF}

*** Test Cases ***
Run Generic Fault Point
    Execute Command    $scenario="${REPORT_SCENARIO}"
    Execute Command    $fault_at=${FAULT_AT}
    Execute Command    $total_writes=${TOTAL_WRITES}
    Execute Command    $result_file="${RESULT_FILE}"
    Execute Command    $include_metadata_faults=${INCLUDE_METADATA_FAULTS}
    Execute Command    $evaluation_mode="${EVALUATION_MODE}"
    Run Keyword If    '${BOOT_MODE}' != '${EMPTY}'    Execute Command    $boot_mode="${BOOT_MODE}"

    Run Keyword If    '${WRITE_GRANULARITY}' != '${EMPTY}'    Execute Command    $write_granularity=${WRITE_GRANULARITY}
    Run Keyword If    '${ACTIVE_BASE}' != '${EMPTY}'    Execute Command    $active_base=${ACTIVE_BASE}
    Run Keyword If    '${STAGING_BASE}' != '${EMPTY}'    Execute Command    $staging_base=${STAGING_BASE}
    Run Keyword If    '${NVM_CTRL_PATH}' != '${EMPTY}'    Execute Command    $nvm_ctrl_path="${NVM_CTRL_PATH}"
    Run Keyword If    '${SLOT_A_BASE}' != '${EMPTY}'    Execute Command    $slot_a_base=${SLOT_A_BASE}
    Run Keyword If    '${SLOT_B_BASE}' != '${EMPTY}'    Execute Command    $slot_b_base=${SLOT_B_BASE}
    Run Keyword If    '${SLOT_SIZE}' != '${EMPTY}'    Execute Command    $slot_size=${SLOT_SIZE}
    Run Keyword If    '${META_BASE_0}' != '${EMPTY}'    Execute Command    $meta_base_0=${META_BASE_0}
    Run Keyword If    '${META_BASE_1}' != '${EMPTY}'    Execute Command    $meta_base_1=${META_BASE_1}
    Run Keyword If    '${META_SIZE}' != '${EMPTY}'    Execute Command    $meta_size=${META_SIZE}
    Run Keyword If    '${BOOTLOADER_ENTRY}' != '${EMPTY}'    Execute Command    $bootloader_entry=${BOOTLOADER_ENTRY}
    Run Keyword If    '${RUN_DURATION}' != '${EMPTY}'    Execute Command    $run_duration="${RUN_DURATION}"
    Execute Command    $trace_execution=${TRACE_EXECUTION}
    Run Keyword If    '${TRACE_FILE}' != '${EMPTY}'    Execute Command    $trace_file="${TRACE_FILE}"
    ${resolved_slot_a_image}=    Run Keyword If    '${SLOT_A_IMAGE_FILE}' != '${EMPTY}'    Resolve Path    ${SLOT_A_IMAGE_FILE}
    Run Keyword If    '${SLOT_A_IMAGE_FILE}' != '${EMPTY}'    Execute Command    $slot_a_image_file="${resolved_slot_a_image}"
    ${resolved_slot_b_image}=    Run Keyword If    '${SLOT_B_IMAGE_FILE}' != '${EMPTY}'    Resolve Path    ${SLOT_B_IMAGE_FILE}
    Run Keyword If    '${SLOT_B_IMAGE_FILE}' != '${EMPTY}'    Execute Command    $slot_b_image_file="${resolved_slot_b_image}"
    Run Keyword If    '${OTA_HEADER_SIZE}' != '${EMPTY}'    Execute Command    $ota_header_size=${OTA_HEADER_SIZE}

    ${resolved_fault_script}=    Resolve Path    ${FAULT_POINT_SCRIPT}
    Load Generic Firmware

    Execute Script    ${resolved_fault_script}

    File Should Exist    ${RESULT_FILE}
