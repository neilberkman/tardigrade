import base64
import json
import os
import struct
import sys
import time as _time

from Antmicro.Renode.Peripherals.CPU import RegisterValue

def log(msg):
    sys.stderr.write('[resc] {}\n'.format(msg))
    sys.stderr.flush()

try:
    integer_types = (int, long)
except NameError:
    integer_types = (int,)

try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)


def _json_safe(value):
    if value is None or isinstance(value, (bool, float) + string_types):
        return value
    if isinstance(value, integer_types):
        return int(value)
    if isinstance(value, dict):
        return {
            str(k): _json_safe(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, set):
        return [_json_safe(v) for v in sorted(value)]
    try:
        return int(value)
    except Exception:
        pass
    try:
        return float(value)
    except Exception:
        pass
    return str(value)


def _json_dump_text(value):
    return json.dumps(_json_safe(value), sort_keys=True)

bus = monitor.Machine.SystemBus


def _bus_load_elf(path):
    """Load ELF. Re-derives bus from monitor to avoid stale references after machine Reset."""
    _p = str(path)
    _bus = monitor.Machine.SystemBus
    try:
        _bus.LoadELF(_p)
        return
    except Exception:
        pass
    # Extension method not available — use inline python command.
    _pf = _p.replace('\\', '/')
    monitor.Parse("python \"monitor.Machine.SystemBus.LoadELF(r'{}')\"".format(_pf))


def _bus_load_binary(path, addr):
    """Load binary. Re-derives bus from monitor to avoid stale references after machine Reset."""
    _p = str(path)
    _a = int(addr)
    _bus = monitor.Machine.SystemBus
    try:
        _bus.LoadBinary(_p, _a)
        return
    except Exception:
        pass
    _pf = _p.replace('\\', '/')
    monitor.Parse("python \"monitor.Machine.SystemBus.LoadBinary(r'{}', {})\"".format(_pf, _a))


# Sentinel value used to disarm fault injection (max uint64).
_DISARM_SENTINEL = 18446744073709551615

# Write fault mode codes shared between run_execute_fault and run_phase2_fault.
# For flash/NVMC backends: WriteFaultMode 0=power_loss, 1=bit_corruption, etc.
# For OTP backends: BlowFaultMode 0=partial_program, 1=stuck_bit, 2=read_disturb, 3=overblow.
# OTP wire codes map to their BlowFaultMode integers directly.
_WRITE_FAULT_MODE = {
    'w': 0, 'b': 1, 's': 2, 'r': 3, 'd': 4, 'l': 5, 'g': 6, 'x': 3,
    'op': 0, 'os': 1, 'od': 2, 'oo': 3,
}

def get_optional_var(name, default=''):
    try:
        value = monitor.GetVariable(name)
    except Exception:
        return default
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default

def get_optional_int_var(names, default=None):
    if not isinstance(names, (list, tuple)):
        names = (names,)
    for name in names:
        raw = get_optional_var(name, '')
        if not raw:
            continue
        try:
            return int(raw, 0)
        except Exception:
            continue
    return default


# ---------------------------------------------------------------------------
# Flash backend selection — unified backend object model.
#
# resolve_backend() determines the backend kind ('mram', 'fast', 'slow'),
# resolves all peripheral handles, and pre-computes capabilities.  The
# returned dict is the single source of truth for all backend dispatch.
#
# $flash_backend must name the sysbus peripheral (e.g. faultFlash, nvm_ctrl,
# mram).  The profile YAML declares this; the resc looks it up and fails if
# it is missing or incompatible.
# ---------------------------------------------------------------------------

def resolve_backend():
    flash_backend_var = str(monitor.GetVariable('flash_backend')).strip()
    if not flash_backend_var:
        raise Exception(
            'flash_backend not set.  Every profile must declare '
            'flash_backend: <sysbus-name> (e.g. faultFlash, nvm_ctrl, mram).'
        )

    backend_name = 'sysbus.' + flash_backend_var if not flash_backend_var.startswith('sysbus.') else flash_backend_var
    try:
        backend_obj = monitor.Machine[backend_name]
    except:
        raise Exception(
            'flash_backend "{}" not found on sysbus. '
            'Check that the platform .repl registers this peripheral.'.format(flash_backend_var)
        )

    # Classify the backend path.
    if 'otp' in backend_name.lower():
        kind = 'otp'
    elif 'mram' in backend_name.lower():
        kind = 'mram'
    elif 'nvm_ctrl' in backend_name.lower():
        kind = 'slow'
    else:
        kind = 'fast'

    # Optional separate NVM controller (e.g. command-register controller in
    # front of MRAM memory).  Enables command_drop fault injection.
    controller = None
    ctrl_sysbus_name = None
    nvm_controller_var = str(monitor.GetVariable('nvm_controller')).strip()
    if nvm_controller_var and nvm_controller_var.lower() not in ('', 'none'):
        ctrl_sysbus_name = 'sysbus.' + nvm_controller_var if not nvm_controller_var.startswith('sysbus.') else nvm_controller_var
        try:
            controller = monitor.Machine[ctrl_sysbus_name]
        except:
            raise Exception(
                'nvm_controller "{}" not found on sysbus. '
                'Check that the platform .repl registers this peripheral.'.format(nvm_controller_var)
            )

    # Pre-compute command fault capability.
    supports_command_fault = False
    command_fault_reason = ''
    if controller is None:
        command_fault_reason = '{}_backend_no_command_controller'.format(kind)
    else:
        cmd_required = ['FaultAtCommandExecution', 'CommandFaultMode',
                        'CommandFaultFired', 'CommandExecutions']
        cmd_missing = [n for n in cmd_required if not hasattr(controller, n)]
        if cmd_missing:
            command_fault_reason = 'backend_missing_command_fault_properties: {}'.format(
                ', '.join(cmd_missing))
        else:
            supports_command_fault = True

    # Optional OTP peripheral (separate from flash backend).
    otp = None
    otp_sysbus_name = None
    otp_var = get_optional_var('otp_peripheral', '')
    if otp_var and otp_var.lower() not in ('', 'none'):
        otp_sysbus_name = 'sysbus.' + otp_var if not otp_var.startswith('sysbus.') else otp_var
        try:
            otp = monitor.Machine[otp_sysbus_name]
        except:
            log('WARNING: otp_peripheral "{}" not found on sysbus'.format(otp_var))

    # Optional I2C fault proxy peripheral for I2C bus fault injection.
    i2c_proxy = None
    i2c_sysbus_name = None
    i2c_var = get_optional_var('i2c_fault_peripheral', '')
    if i2c_var and i2c_var.lower() not in ('', 'none'):
        i2c_sysbus_name = 'sysbus.' + i2c_var if not i2c_var.startswith('sysbus.') else i2c_var
        try:
            i2c_proxy = monitor.Machine[i2c_sysbus_name]
        except:
            log('WARNING: i2c_fault_peripheral "{}" not found on sysbus'.format(i2c_var))

    # Pre-compute I2C fault capability.
    supports_i2c_fault = False
    i2c_fault_reason = ''
    if i2c_proxy is None:
        i2c_fault_reason = 'no_i2c_fault_peripheral'
    else:
        i2c_required = ['FaultAtTransaction', 'FaultType', 'FaultFired', 'TotalTransactions']
        i2c_missing = [n for n in i2c_required if not hasattr(i2c_proxy, n)]
        if i2c_missing:
            i2c_fault_reason = 'i2c_peripheral_missing_properties: {}'.format(
                ', '.join(i2c_missing))
        else:
            supports_i2c_fault = True

    return {
        'kind': kind,
        'data': backend_obj,
        'controller': controller,
        'backend_sysbus_name': backend_name,
        'ctrl_sysbus_name': ctrl_sysbus_name,
        'supports_command_fault': supports_command_fault,
        'command_fault_reason': command_fault_reason,
        'otp': otp,
        'otp_sysbus_name': otp_sysbus_name,
        'i2c_proxy': i2c_proxy,
        'i2c_sysbus_name': i2c_sysbus_name,
        'supports_i2c_fault': supports_i2c_fault,
        'i2c_fault_reason': i2c_fault_reason,
    }

backend = resolve_backend()

_cached_erase_page = None
_cached_initial_flash = None
_cached_phase1_snapshot_path = None
_cached_recovery_snapshot_path = None
_machine_selector = '0'


def refresh_runtime_handles():
    global backend, bus
    bus = monitor.Machine.SystemBus
    backend['data'] = monitor.Machine[backend['backend_sysbus_name']]
    if backend['ctrl_sysbus_name']:
        backend['controller'] = monitor.Machine[backend['ctrl_sysbus_name']]
    if backend.get('otp_sysbus_name'):
        try:
            backend['otp'] = monitor.Machine[backend['otp_sysbus_name']]
        except:
            pass
    if backend.get('i2c_sysbus_name'):
        try:
            backend['i2c_proxy'] = monitor.Machine[backend['i2c_sysbus_name']]
        except:
            pass

# Read monitor variables.
result_file = str(monitor.GetVariable('result_file'))
calibration_mode = str(monitor.GetVariable('calibration_mode')).lower() in ('1', 'true', 'yes')
evaluation_mode = str(monitor.GetVariable('evaluation_mode')).strip().lower()
if evaluation_mode not in ('execute', 'state'):
    evaluation_mode = 'state'
run_duration = str(monitor.GetVariable('run_duration'))
max_step_limit = int(monitor.GetVariable('max_step_limit'))
max_writes_cap = int(monitor.GetVariable('max_writes_cap'))
progress_stall_timeout_raw = str(monitor.GetVariable('progress_stall_timeout_s')).strip()
try:
    progress_stall_timeout_s = float(progress_stall_timeout_raw)
except Exception:
    progress_stall_timeout_s = 20.0
if progress_stall_timeout_s < 0:
    progress_stall_timeout_s = 0.0
expect_control_outcome = str(monitor.GetVariable('expect_control_outcome')).strip().lower()
no_boot_zero_write_slices_raw = str(monitor.GetVariable('no_boot_zero_write_slices')).strip()
no_boot_min_emulated_s_raw = str(monitor.GetVariable('no_boot_min_emulated_s')).strip()
try:
    no_boot_zero_write_slices = int(no_boot_zero_write_slices_raw)
except Exception:
    no_boot_zero_write_slices = 10
if no_boot_zero_write_slices < 1:
    no_boot_zero_write_slices = 1
try:
    no_boot_min_emulated_s = float(no_boot_min_emulated_s_raw)
except Exception:
    no_boot_min_emulated_s = 0.1
if no_boot_min_emulated_s < 0:
    no_boot_min_emulated_s = 0.0
sweep_diff_lookahead_raw = str(monitor.GetVariable('sweep_diff_lookahead')).strip()
try:
    sweep_diff_lookahead = int(sweep_diff_lookahead_raw, 0)
except Exception:
    sweep_diff_lookahead = 2147483647
if sweep_diff_lookahead < 1:
    sweep_diff_lookahead = 1
if sweep_diff_lookahead > 2147483647:
    sweep_diff_lookahead = 2147483647
postmortem_dump_no_boot = str(monitor.GetVariable('postmortem_dump_no_boot')).strip().lower() in ('1', 'true', 'yes')
postmortem_dump_header_bytes_raw = str(monitor.GetVariable('postmortem_dump_header_bytes')).strip()
try:
    postmortem_dump_header_bytes = int(postmortem_dump_header_bytes_raw, 0)
except Exception:
    postmortem_dump_header_bytes = 4096
if postmortem_dump_header_bytes < 32:
    postmortem_dump_header_bytes = 32
resume_trace_no_boot = str(monitor.GetVariable('resume_trace_no_boot')).strip().lower() in ('1', 'true', 'yes')
resume_trace_max_ops_raw = str(monitor.GetVariable('resume_trace_max_ops')).strip()
try:
    resume_trace_max_ops = int(resume_trace_max_ops_raw, 0)
except Exception:
    resume_trace_max_ops = 1024
if resume_trace_max_ops < 1:
    resume_trace_max_ops = 1
resume_trace_time_slice = str(monitor.GetVariable('resume_trace_time_slice')).strip()
if not resume_trace_time_slice:
    resume_trace_time_slice = '0.02'
calibration_time_slice = str(monitor.GetVariable('calibration_time_slice')).strip()
if not calibration_time_slice:
    calibration_time_slice = '0.02'
phase2_time_slice = str(monitor.GetVariable('phase2_time_slice')).strip()
if not phase2_time_slice:
    phase2_time_slice = '0.05'
resume_trace_wall_timeout_raw = str(monitor.GetVariable('resume_trace_wall_timeout_s')).strip()
try:
    resume_trace_wall_timeout_s = float(resume_trace_wall_timeout_raw)
except Exception:
    resume_trace_wall_timeout_s = 30.0
if resume_trace_wall_timeout_s <= 0:
    resume_trace_wall_timeout_s = 30.0
boot_cycles_raw = str(monitor.GetVariable('boot_cycles')).strip()
repo_root = get_optional_var('repo_root', '')
enable_machine_snapshots = str(monitor.GetVariable('enable_machine_snapshots')).strip().lower() in ('1', 'true', 'yes')
boot_cycle_hook = get_optional_var('boot_cycle_hook', '')
expected_rollback_at_cycle = get_optional_int_var('expected_rollback_at_cycle')
try:
    boot_cycles = int(boot_cycles_raw, 0) if boot_cycles_raw else 1
except Exception:
    boot_cycles = 1
if boot_cycles < 1:
    boot_cycles = 1

# Confirm-cycle configuration.
_confirm_cycle_enabled = get_optional_var('confirm_cycle_enabled', 'false').lower() in ('1', 'true', 'yes')
_confirm_cycle_function = get_optional_var('confirm_cycle_function', '')
_confirm_cycle_assertions_raw = get_optional_var('confirm_cycle_assertions', '')
_confirm_cycle_assertions = []
if _confirm_cycle_assertions_raw:
    try:
        _confirm_cycle_assertions = json.loads(_confirm_cycle_assertions_raw)
    except Exception:
        pass
_confirm_cycle_ratchet_version = get_optional_int_var('confirm_cycle_ratchet_version')
_firmware_elf = get_optional_var('firmware_elf', '')

# Batch vs single mode.
fault_points_csv = str(monitor.GetVariable('fault_points_csv')).strip()
if fault_points_csv:
    fault_points = [int(x.strip()) for x in fault_points_csv.split(',') if x.strip()]
else:
    fault_points = [int(monitor.GetVariable('fault_at'))]
batch_mode = len(fault_points) > 1 or bool(fault_points_csv)

# Slot geometry.
slot_exec_base = int(str(monitor.GetVariable('slot_exec_base')), 0)
slot_exec_size = int(str(monitor.GetVariable('slot_exec_size')), 0)
slot_staging_base = int(str(monitor.GetVariable('slot_staging_base')), 0)
slot_staging_size = int(str(monitor.GetVariable('slot_staging_size')), 0)
slot_tertiary_base = get_optional_int_var('slot_tertiary_base', None)
slot_tertiary_size = get_optional_int_var('slot_tertiary_size', None)
slot_recovery_base = get_optional_int_var('slot_recovery_base', None)
slot_recovery_size = get_optional_int_var('slot_recovery_size', None)
sram_start = int(str(monitor.GetVariable('sram_start')), 0)
sram_end = int(str(monitor.GetVariable('sram_end')), 0)
bootloader_entry = int(str(monitor.GetVariable('bootloader_entry')), 0)
bootloader_elf = str(monitor.GetVariable('bootloader_elf')).strip()
write_granularity = int(str(monitor.GetVariable('write_granularity')).strip())

# NVM base address: the lowest address in the NVM region.  Used for converting
# absolute bus addresses to peripheral-relative offsets (e.g. read fault
# injection).  For MRAM the bootloader sits at MRAM offset 0, so
# bootloader_entry == MRAM base.  For NRF52 flash starts at 0x0.
nvm_base_address = min(bootloader_entry, slot_exec_base, slot_staging_base)

# Image paths for reload between batch iterations.
image_staging_path = str(monitor.GetVariable('image_staging_path')).strip()
image_exec_path = str(monitor.GetVariable('image_exec_path')).strip()
image_tertiary_path = get_optional_var('image_tertiary_path', '')
image_recovery_path = get_optional_var('image_recovery_path', '')

# Residual image: load a prior (larger) image first, then overwrite with
# the actual image, leaving stale tail bytes from the prior image.
residual_image_slot = get_optional_var('residual_image_slot', '')
residual_image_prior = get_optional_var('residual_image_prior', '')
residual_image_fill_raw = get_optional_var('residual_image_fill', '')
residual_image_fill = None
if residual_image_fill_raw:
    try:
        residual_image_fill = int(residual_image_fill_raw, 0)
    except Exception:
        residual_image_fill = None
residual_image_enabled = bool(residual_image_slot and (residual_image_prior or residual_image_fill is not None))

# Max reset vector offset: flag if the reset vector points beyond
# this offset from slot base (authenticated image boundary check).
max_reset_vector_offset_raw = get_optional_var('max_reset_vector_offset', '')
max_reset_vector_offset = None
if max_reset_vector_offset_raw:
    try:
        max_reset_vector_offset = int(max_reset_vector_offset_raw, 0)
    except Exception:
        max_reset_vector_offset = None

# Success criteria.
success_vtor_slot = str(monitor.GetVariable('success_vtor_slot')).strip()
success_vector_offset_raw = str(monitor.GetVariable('success_vector_offset')).strip()
try:
    success_vector_offset = int(success_vector_offset_raw, 0) if success_vector_offset_raw else 0
except Exception:
    success_vector_offset = 0
if success_vector_offset < 0:
    success_vector_offset = 0
success_pc_slot_raw = str(monitor.GetVariable('success_pc_slot')).strip()
success_pc_slot = success_pc_slot_raw if success_pc_slot_raw else None

success_marker_addr_raw = str(monitor.GetVariable('success_marker_addr')).strip()
success_marker_value_raw = str(monitor.GetVariable('success_marker_value')).strip()
success_marker_addr = int(success_marker_addr_raw, 0) if success_marker_addr_raw and success_marker_addr_raw != '0' else 0
success_marker_value = int(success_marker_value_raw, 0) if success_marker_value_raw and success_marker_value_raw != '0' else 0

# Image hash mode.
success_image_hash = str(monitor.GetVariable('success_image_hash')).strip().lower() in ('1', 'true', 'yes')
success_image_hash_slot = str(monitor.GetVariable('success_image_hash_slot')).strip()
image_exec_sha256 = str(monitor.GetVariable('image_exec_sha256')).strip()
image_staging_sha256 = str(monitor.GetVariable('image_staging_sha256')).strip()
expected_exec_sha256 = str(monitor.GetVariable('expected_exec_sha256')).strip()
success_otadata_expect_raw = str(monitor.GetVariable('success_otadata_expect')).strip()
success_otadata_expect_scope = str(monitor.GetVariable('success_otadata_expect_scope')).strip().lower()
if success_otadata_expect_scope not in ('always', 'control'):
    success_otadata_expect_scope = 'always'

# Security policy: anti-rollback enforcement.
security_anti_rollback = str(monitor.GetVariable('security_anti_rollback')).strip().lower() in ('1', 'true', 'yes')

# Metadata delta tracking: parse field specs from robot variable.
# Format: "0xADDR,name[,min=N][,max=N][,when=COND];..."
metadata_delta_fields_raw = get_optional_var('metadata_delta_fields', '')
metadata_delta_fields = []
if metadata_delta_fields_raw:
    for spec in metadata_delta_fields_raw.split(';'):
        spec = spec.strip()
        if not spec:
            continue
        parts = spec.split(',')
        if len(parts) < 2:
            continue
        addr = int(parts[0].strip(), 0)
        name = parts[1].strip()
        min_delta = None
        max_delta = None
        when = 'always'
        for p in parts[2:]:
            p = p.strip()
            if p.startswith('min='):
                min_delta = int(p[4:])
            elif p.startswith('max='):
                max_delta = int(p[4:])
            elif p.startswith('when='):
                when = p[5:]
        metadata_delta_fields.append({
            'address': addr,
            'name': name,
            'min_delta': min_delta,
            'max_delta': max_delta,
            'when': when,
        })
metadata_delta_enabled = len(metadata_delta_fields) > 0

_base_phase_context = {
    'boot_cycles': int(boot_cycles),
    'boot_cycle_hook': boot_cycle_hook,
    'expected_rollback_at_cycle': expected_rollback_at_cycle,
    'success_criteria': {
        'vtor_in_slot': success_vtor_slot,
        'vector_table_offset': int(success_vector_offset),
        'pc_in_slot': success_pc_slot or '',
        'marker_address': int(success_marker_addr),
        'marker_value': int(success_marker_value),
        'image_hash': bool(success_image_hash),
        'image_hash_slot': success_image_hash_slot or '',
        'image_exec_sha256': image_exec_sha256,
        'image_staging_sha256': image_staging_sha256,
        'expected_exec_sha256': expected_exec_sha256,
        'otadata_expect': {},
        'otadata_expect_scope': success_otadata_expect_scope,
    },
}


def _apply_phase_context(phase=None):
    global boot_cycles, boot_cycle_hook, expected_rollback_at_cycle
    global success_vtor_slot, success_vector_offset, success_pc_slot
    global success_marker_addr, success_marker_value
    global success_image_hash, success_image_hash_slot
    global image_exec_sha256, image_staging_sha256, expected_exec_sha256
    global success_otadata_expect, success_otadata_expect_scope

    context = _base_phase_context if phase is None else phase
    criteria = context.get('success_criteria', {}) if isinstance(context, dict) else {}
    boot_cycles = max(1, int(context.get('boot_cycles', _base_phase_context['boot_cycles']) or 1))
    boot_cycle_hook = str(
        context.get('boot_cycle_hook', _base_phase_context['boot_cycle_hook']) or ''
    ).strip()
    expected_rollback_at_cycle = context.get(
        'expected_rollback_at_cycle',
        _base_phase_context['expected_rollback_at_cycle'],
    )
    if expected_rollback_at_cycle is not None:
        expected_rollback_at_cycle = int(expected_rollback_at_cycle)
    success_vtor_slot = str(criteria.get('vtor_in_slot', _base_phase_context['success_criteria']['vtor_in_slot']) or '')
    success_vector_offset = int(
        criteria.get('vector_table_offset', _base_phase_context['success_criteria']['vector_table_offset']) or 0
    )
    success_pc_slot = str(
        criteria.get('pc_in_slot', _base_phase_context['success_criteria']['pc_in_slot']) or ''
    ).strip() or None
    success_marker_addr = int(
        criteria.get('marker_address', _base_phase_context['success_criteria']['marker_address']) or 0
    )
    success_marker_value = int(
        criteria.get('marker_value', _base_phase_context['success_criteria']['marker_value']) or 0
    )
    success_image_hash = bool(
        criteria.get('image_hash', _base_phase_context['success_criteria']['image_hash'])
    )
    success_image_hash_slot = str(
        criteria.get('image_hash_slot', _base_phase_context['success_criteria']['image_hash_slot']) or ''
    ).strip()
    image_exec_sha256 = str(
        criteria.get('image_exec_sha256', _base_phase_context['success_criteria']['image_exec_sha256']) or ''
    ).strip()
    image_staging_sha256 = str(
        criteria.get('image_staging_sha256', _base_phase_context['success_criteria']['image_staging_sha256']) or ''
    ).strip()
    expected_exec_sha256 = str(
        criteria.get('expected_exec_sha256', _base_phase_context['success_criteria']['expected_exec_sha256']) or ''
    ).strip()
    success_otadata_expect = criteria.get(
        'otadata_expect',
        _base_phase_context['success_criteria']['otadata_expect'],
    ) or {}
    success_otadata_expect_scope = str(
        criteria.get(
            'otadata_expect_scope',
            _base_phase_context['success_criteria']['otadata_expect_scope'],
        )
        or 'always'
    ).strip().lower()
    if success_otadata_expect_scope not in ('always', 'control'):
        success_otadata_expect_scope = 'always'

# Per-fault-type success criteria overrides.
# Prefer file-based transport (avoids Robot->Renode variable escaping).
# Falls back to base64-encoded variable if no file is set.
_success_criteria_overrides = {}
_overrides_file = get_optional_var('success_criteria_overrides_file', '')
if _overrides_file:
    try:
        with open(_overrides_file, 'r') as _f:
            _success_criteria_overrides = json.loads(_f.read())
        log('success_criteria_overrides: loaded {} fault type overrides from file'.format(
            len(_success_criteria_overrides)))
    except Exception as e:
        log('WARNING: failed to read success_criteria_overrides_file: {}'.format(e))
else:
    _overrides_raw = get_optional_var('success_criteria_overrides', '')
    if _overrides_raw:
        try:
            import base64
            _padded = _overrides_raw + '=' * (-len(_overrides_raw) % 4)
            _decoded = base64.b64decode(_padded).decode()
            _success_criteria_overrides = json.loads(_decoded)
            log('success_criteria_overrides: loaded {} fault type overrides from base64'.format(
                len(_success_criteria_overrides)))
        except Exception as e:
            log('WARNING: failed to parse success_criteria_overrides: {}'.format(e))

# Map single-char fault type codes to full fault type names for override lookup.
_FAULT_CODE_TO_NAME = {
    'w': 'power_loss',
    'e': 'interrupted_erase',
    'a': 'multi_sector_atomicity',
    'b': 'bit_corruption',
    's': 'silent_write_failure',
    'g': 'driver_error',
    'x': 'rc_injection',
    'd': 'write_disturb',
    'l': 'wear_leveling_corruption',
    'r': 'write_rejection',
    't': 'reset_at_time',
    'f': 'read_bit_flip',
    'k': 'command_drop',
    'i': 'instruction_skip',
    'h': 'hook_fault',
    'cc': 'confirm_cycle',
    'm': 'metadata_fault',
    'p2': 'phase2_fault',
    'op': 'otp_partial_program',
    'os': 'otp_stuck_bit',
    'od': 'otp_read_disturb',
    'oo': 'otp_overblow',
    'nv': 'nvs_corruption',
    'in': 'i2c_nack',
    'it': 'i2c_timeout',
    'ib': 'i2c_bit_flip',
    'ic': 'i2c_truncated',
    'iw': 'i2c_wrong_address',
}


def get_effective_criteria(fault_type_code):
    # Return effective success criteria for a given fault type code.
    # Merges per-fault-type overrides (from the profile) over the global
    # criteria.  Returns a dict with the effective values.  If no override
    # exists for the fault type, returns the global criteria unchanged.
    # The control run (fault_type_code='control' or negative fault_at)
    # always uses global criteria.
    global_criteria = {
        'vtor_slot': success_vtor_slot,
        'image_hash': success_image_hash,
        'image_hash_slot': success_image_hash_slot,
    }
    if not _success_criteria_overrides or not fault_type_code:
        return global_criteria
    # Resolve code to name.
    fault_name = _FAULT_CODE_TO_NAME.get(str(fault_type_code), str(fault_type_code))
    overrides = _success_criteria_overrides.get(fault_name)
    if not overrides:
        return global_criteria
    effective = dict(global_criteria)
    if 'vtor_in_slot' in overrides:
        effective['vtor_slot'] = str(overrides['vtor_in_slot'])
    if 'image_hash' in overrides:
        effective['image_hash'] = str(overrides['image_hash']).lower() in ('1', 'true', 'yes')
    if 'image_hash_slot' in overrides:
        effective['image_hash_slot'] = str(overrides['image_hash_slot'])
    return effective


# Pre-boot state binary.
pre_boot_bin = str(monitor.GetVariable('pre_boot_state_bin')).strip()
pre_boot_write_count = 0
if pre_boot_bin:
    try:
        pbs_size = os.path.getsize(pre_boot_bin)
        pre_boot_write_count = pbs_size // 8
    except Exception:
        pass

update_sequence_file = get_optional_var('update_sequence_file', '')
update_sequence_data = None
update_sequence_phases = []
update_sequence_fault_phase_index = -1
update_sequence_fault_phase = None
if update_sequence_file:
    with open(update_sequence_file, 'r') as update_sequence_fp:
        update_sequence_data = json.loads(update_sequence_fp.read())
    if not isinstance(update_sequence_data, dict):
        raise RuntimeError('update_sequence_file must contain a JSON object')
    raw_phases = update_sequence_data.get('phases', [])
    if not isinstance(raw_phases, list):
        raise RuntimeError('update_sequence_file.phases must be a list')
    update_sequence_phases = raw_phases
    update_sequence_fault_phase_index = int(update_sequence_data.get('fault_phase_index', -1))
    if 0 <= update_sequence_fault_phase_index < len(update_sequence_phases):
        update_sequence_fault_phase = update_sequence_phases[update_sequence_fault_phase_index]
update_sequence_enabled = bool(update_sequence_phases) and update_sequence_fault_phase is not None
if update_sequence_enabled:
    log('update_sequence: loaded {} phases (fault phase #{}, {})'.format(
        len(update_sequence_phases),
        update_sequence_fault_phase_index,
        update_sequence_fault_phase.get('name', 'unnamed'),
    ))
    if backend['kind'] == 'slow':
        raise RuntimeError(
            'update_sequence currently requires fast or mram flash backends'
        )

# Setup script.
setup_script = str(monitor.GetVariable('setup_script')).strip()
state_probe = str(monitor.GetVariable('state_probe')).strip()

# Fault type support: 'write', 'erase', or 'both'.
# fault_types controls which operations are tracked during calibration.
# fault_type_csv provides per-fault-point type:
#   write-based: 'w' power_loss, 'b' bit_corruption, 's' silent_write_failure,
#                'g' driver_error, 'x' rc_injection, 'd' write_disturb,
#                'l' wear_leveling_corruption, 'r' write_rejection, 't' reset_at_time
#   erase-based: 'e' interrupted_erase, 'a' multi_sector_atomicity
#   read-based:  'f' read_bit_flip (transient one-shot read corruption)
#   cpu-based:   'i' instruction_skip (voltage-glitch NOP, encoded as 'i:0xADDR')
fault_types_raw = str(monitor.GetVariable('fault_types')).strip().lower()
if fault_types_raw in ('both', 'write_and_erase', 'write,erase'):
    fault_types_mode = 'both'
elif fault_types_raw == 'erase':
    fault_types_mode = 'erase'
else:
    fault_types_mode = 'write'

fault_type_csv_raw = str(monitor.GetVariable('fault_type_csv')).strip()
if fault_type_csv_raw:
    fault_type_list = [x.strip() for x in fault_type_csv_raw.split(',') if x.strip()]
else:
    fault_type_list = []

# Read-fault config from profile (robot variables).
read_fault_seed = int(str(monitor.GetVariable('read_fault_seed')).strip() or '0')
read_fault_bit_flips = int(str(monitor.GetVariable('read_fault_bit_flips')).strip() or '0')
_rf_prob_str = str(monitor.GetVariable('read_fault_probability')).strip()
read_fault_probability = float(_rf_prob_str) if _rf_prob_str else 1.0
_rf_regions_str = str(monitor.GetVariable('read_fault_regions')).strip()
read_fault_regions = []
if _rf_regions_str:
    for pair in _rf_regions_str.split(','):
        pair = pair.strip()
        if '-' in pair:
            s, e = pair.split('-', 1)
            read_fault_regions.append((int(s, 0), int(e, 0)))
        elif ':' in pair:
            s, e = pair.split(':', 1)
            read_fault_regions.append((int(s, 0), int(e, 0)))
read_fault_preflight = {
    'checked': False,
    'supported': None,
    'reason': '',
    'backend': '',
}

# NVS region config for nvs_corruption fault type.
_nvs_region_addr_raw = get_optional_var('nvs_region_addr', '')
_nvs_region_size_raw = get_optional_var('nvs_region_size', '')
nvs_region_addr = int(_nvs_region_addr_raw, 0) if _nvs_region_addr_raw else None
nvs_region_size = int(_nvs_region_size_raw, 0) if _nvs_region_size_raw else None
nvs_snapshot_path = get_optional_var('nvs_region_snapshot', '')
_nvs_modes_raw = get_optional_var('nvs_corruption_modes', '')
nvs_corruption_modes = [m.strip() for m in _nvs_modes_raw.split(',') if m.strip()] if _nvs_modes_raw else []
nvs_corruption_seed = int(get_optional_var('nvs_corruption_seed', '0') or '0')
_nvs_clean_data = None

def _load_nvs_clean_data():
    # Load or synthesize the clean NVS region data (lazy, cached).
    global _nvs_clean_data
    if _nvs_clean_data is not None:
        return _nvs_clean_data
    if nvs_region_addr is None or nvs_region_size is None:
        _nvs_clean_data = b''
        return _nvs_clean_data
    if nvs_snapshot_path and os.path.isfile(nvs_snapshot_path):
        with open(nvs_snapshot_path, 'rb') as f:
            _nvs_clean_data = f.read()[:nvs_region_size]
    else:
        # Read current NVS region from flash.
        raw = bus.ReadBytes(nvs_region_addr, nvs_region_size)
        _nvs_clean_data = to_py_bytes(raw)
    # Pad to region_size.
    if len(_nvs_clean_data) < nvs_region_size:
        _nvs_clean_data = _nvs_clean_data + b'\xFF' * (nvs_region_size - len(_nvs_clean_data))
    return _nvs_clean_data

# Slot lookup table.
slot_ranges = {
    'exec': (slot_exec_base, slot_exec_base + slot_exec_size),
    'staging': (slot_staging_base, slot_staging_base + slot_staging_size),
}
if slot_tertiary_base is not None and slot_tertiary_size is not None:
    slot_ranges['tertiary'] = (
        slot_tertiary_base,
        slot_tertiary_base + slot_tertiary_size,
    )
if slot_recovery_base is not None and slot_recovery_size is not None:
    slot_ranges['recovery'] = (
        slot_recovery_base,
        slot_recovery_base + slot_recovery_size,
    )

slot_load_addresses = {
    'exec': slot_exec_base,
    'staging': slot_staging_base,
}
if slot_tertiary_base is not None:
    slot_load_addresses['tertiary'] = slot_tertiary_base
if slot_recovery_base is not None:
    slot_load_addresses['recovery'] = slot_recovery_base

_cached_update_sequence_fault_flash = None


def _update_sequence_summary():
    if not update_sequence_enabled:
        return None
    return {
        'fault_phase_index': int(update_sequence_fault_phase_index),
        'fault_phase': update_sequence_fault_phase.get('name', ''),
        'fault_phase_start_images': dict(update_sequence_fault_phase.get('start_images', {})),
        'fault_phase_image_overlays': dict(update_sequence_fault_phase.get('images', {})),
        'fault_phase_pre_boot_writes': len(update_sequence_fault_phase.get('pre_boot_state', [])),
        'phases': [str(phase.get('name', '')) for phase in update_sequence_phases],
        'clean_phases': [
            str(phase.get('name', ''))
            for phase in update_sequence_phases
            if not bool(phase.get('fault_injection'))
        ],
    }


def annotate_update_sequence_result(result):
    summary = _update_sequence_summary()
    if summary is not None and isinstance(result, dict):
        result['update_sequence'] = summary
    return result


def annotate_boot_span_result(result):
    if not isinstance(result, dict):
        return result
    if (
        'boot_outcome' not in result
        and 'boot_cycles' not in result
        and 'multi_boot_analysis' not in result
    ):
        return result

    boot_cycles = result.get('boot_cycles')
    first_cycle = boot_cycles[0] if isinstance(boot_cycles, list) and boot_cycles else None
    last_cycle = boot_cycles[-1] if isinstance(boot_cycles, list) and boot_cycles else None

    initial_outcome = result.get('initial_boot_outcome')
    initial_slot = result.get('initial_boot_slot')
    if initial_outcome is None:
        if isinstance(first_cycle, dict):
            initial_outcome = first_cycle.get('boot_outcome', result.get('boot_outcome'))
            initial_slot = first_cycle.get('boot_slot', result.get('boot_slot'))
        else:
            initial_outcome = result.get('boot_outcome')
            initial_slot = result.get('boot_slot')

    final_outcome = result.get('final_boot_outcome')
    final_slot = result.get('final_boot_slot')
    if final_outcome is None:
        mba = result.get('multi_boot_analysis')
        if isinstance(mba, dict) and mba.get('final_outcome') is not None:
            final_outcome = mba.get('final_outcome')
            final_slot = mba.get('final_slot')
        elif isinstance(last_cycle, dict):
            final_outcome = last_cycle.get('boot_outcome', result.get('boot_outcome'))
            final_slot = last_cycle.get('boot_slot', result.get('boot_slot'))
        else:
            final_outcome = result.get('boot_outcome')
            final_slot = result.get('boot_slot')

    result['initial_boot_outcome'] = initial_outcome
    result['initial_boot_slot'] = initial_slot
    result['final_boot_outcome'] = final_outcome
    result['final_boot_slot'] = final_slot
    return result

# Sticky state for VTOR detection during execute runs.
sticky_vtor = {'value': 0, 'slot': None, 'captured': False}

def on_vtor_write(val):
    if sticky_vtor['captured']:
        return
    v = as_int(val)
    if v == 0:
        return
    for sn, (s_lo, s_hi) in slot_ranges.items():
        if s_lo <= v < s_hi:
            sticky_vtor['value'] = v
            sticky_vtor['slot'] = sn
            sticky_vtor['captured'] = True
            log('vtor_sticky: captured {} at {}'.format(sn, fmt_u32(v)))
            break

def arm_vtor_watchpoint():
    sticky_vtor['value'] = 0
    sticky_vtor['slot'] = None
    sticky_vtor['captured'] = False
    try:
        # VTOR is at 0xE000ED08.  Watch for writes.
        bus.AddWatchpoint(0xE000ED08, 4, 'on_vtor_write(value)')
    except:
        pass

def disarm_vtor_watchpoint():
    try:
        bus.RemoveWatchpoint(0xE000ED08)
    except:
        pass

# ---------------------------------------------------------------------------
# Hash bypass: skip hash validation functions for faster Phase 2 emulation.
# Patches flash with Thumb instructions (movs r0,#0; bx lr) so the function
# returns 0 immediately.  Applied after each reload_images_cached() since the
# image restore overwrites the patch.
# ---------------------------------------------------------------------------
_bootloader_elf_path = str(monitor.GetVariable('bootloader_elf')).strip()
_nm_lines = None

def _load_elf_nm_lines():
    global _nm_lines
    if _nm_lines is not None:
        return _nm_lines
    _nm_lines = []
    if not _bootloader_elf_path:
        return _nm_lines
    try:
        import subprocess as _sp
        _nm_proc = _sp.Popen(['nm', _bootloader_elf_path], stdout=_sp.PIPE, stderr=_sp.PIPE)
        _nm_stdout, _ = _nm_proc.communicate()
        _nm_proc.wait()
        if hasattr(_nm_stdout, 'decode'):
            _nm_stdout = _nm_stdout.decode('utf-8', errors='replace')
        _nm_rc = _nm_proc.returncode
        if _nm_rc is None:
            _nm_rc = 0 if _nm_stdout else 1
        if _nm_rc == 0:
            _nm_lines = _nm_stdout.splitlines()
            log('elf_symbols: parsed {} symbols from ELF via nm'.format(len(_nm_lines)))
        else:
            log('elf_symbols: nm failed (rc={}), falling back to single-match symbol lookup'.format(_nm_rc))
    except Exception as _e:
        log('elf_symbols: nm not available ({}), falling back to single-match symbol lookup'.format(_e))
    return _nm_lines

def _is_glob_pattern(query):
    for ch in ('*', '?', '['):
        if ch in query:
            return True
    return False

def _resolve_elf_symbol_addresses(sym_name):
    found_addrs = set()
    nm_lines = _load_elf_nm_lines()
    is_glob = _is_glob_pattern(sym_name)
    if is_glob:
        import fnmatch as _fnmatch
        for line in nm_lines:
            parts = line.strip().split()
            if len(parts) >= 3 and _fnmatch.fnmatch(parts[2], sym_name):
                try:
                    found_addrs.add(int(parts[0], 16) & ~1)
                except ValueError:
                    continue
        if found_addrs:
            log('elf_symbols: glob {!r} matched {} address(es)'.format(sym_name, len(found_addrs)))
    else:
        for line in nm_lines:
            parts = line.strip().split()
            if len(parts) >= 3 and parts[2] == sym_name:
                try:
                    found_addrs.add(int(parts[0], 16) & ~1)
                except ValueError:
                    continue
        if not found_addrs:
            try:
                addr = int(bus.GetSymbolAddress(sym_name))
                found_addrs.add(addr & ~1)
                if not nm_lines:
                    log('elf_symbols: WARNING: nm unavailable, only single-match for {}'.format(sym_name))
            except Exception as _sym_err:
                # Try monitor command as last resort
                try:
                    _resp = monitor.Parse('sysbus FindSymbolAt "{}"'.format(sym_name))
                    if _resp and '0x' in str(_resp):
                        import re as _re
                        _m = _re.search(r'0x([0-9a-fA-F]+)', str(_resp))
                        if _m:
                            found_addrs.add(int(_m.group(1), 16) & ~1)
                except Exception:
                    pass
                if not found_addrs:
                    log('elf_symbols: GetSymbolAddress({}) failed: {}'.format(sym_name, _sym_err))
    return sorted(found_addrs)

_hash_bypass_symbols_raw = str(monitor.GetVariable('hash_bypass_symbols')).strip()
_hash_bypass_patches = []
if _hash_bypass_symbols_raw and backend['kind'] in ('fast', 'mram'):
    for sym_name in _hash_bypass_symbols_raw.split(','):
        sym_name = sym_name.strip()
        if not sym_name:
            continue
        found_addrs = _resolve_elf_symbol_addresses(sym_name)
        for addr in found_addrs:
            _hash_bypass_patches.append((addr, sym_name))
            log('hash_bypass: {}=0x{:08X}'.format(sym_name, addr & 0xFFFFFFFF))
        if not found_addrs:
            raise RuntimeError(
                'hash_bypass: symbol {} not found in ELF. Cannot proceed with '
                'bypass — calibration would produce invalid results.'.format(sym_name)
            )

def apply_hash_bypass():
    # ARM Thumb: movs r0, #0 + bx lr = return 0.  Little-endian 32-bit: 0x47702000.
    # Write via sysbus so it works regardless of which memory region the symbol is in
    # (boot_rom vs nvm flash).
    for addr, sym_name in _hash_bypass_patches:
        bus.WriteDoubleWord(addr, 0x47702000)

_hash_bypass_active = len(_hash_bypass_patches) > 0
if _hash_bypass_active:
    log('hash_bypass: {} symbols resolved'.format(len(_hash_bypass_patches)))

# ---------------------------------------------------------------------------
# RC injection: force flash_area_write()-style wrappers to return -EIO after
# a targeted write fault without halting the CPU. This is MCUboot-specific.
# ---------------------------------------------------------------------------
_rc_injection_symbols_raw = get_optional_var('rc_injection_symbols', 'flash_area_write')
_rc_injection_symbols = [sym.strip() for sym in _rc_injection_symbols_raw.split(',') if sym.strip()]
_rc_injection_state = {
    'checked': False,
    'supported': False,
    'reason': '',
    'enabled': False,
    'entry_symbol_by_addr': {},
    'installed_return_hooks': set(),
    'active_symbol': None,
    'active_return_addr': None,
    'injected': False,
    'injected_symbol': None,
    'injected_return_addr': None,
    'return_value': 0xFFFFFFFB,
}

# Pre-resolve rc_injection symbols at load time (like hash_bypass).
# bus.GetSymbolAddress works here; it may fail inside ensure_rc_injection_preflight
# after machine resets.
_rc_injection_pre_resolved = {}
for _rci_sym in _rc_injection_symbols:
    for _rci_addr in _resolve_elf_symbol_addresses(_rci_sym):
        _rc_injection_pre_resolved[_rci_sym] = _rci_addr
        log('rc_injection: pre-resolved {}=0x{:08X}'.format(_rci_sym, _rci_addr & 0xFFFFFFFF))

def _rc_injection_return_hook(cpu, addr):
    current_addr = int(addr) & ~1
    if not _rc_injection_state.get('enabled'):
        return
    if _rc_injection_state.get('active_return_addr') != current_addr:
        return
    if not _rc_injection_state.get('injected') and was_fault_injected():
        cpu.SetRegister(0, RegisterValue.Create(_rc_injection_state['return_value'], 32))
        _rc_injection_state['injected'] = True
        _rc_injection_state['injected_symbol'] = _rc_injection_state.get('active_symbol')
        _rc_injection_state['injected_return_addr'] = current_addr
        log('rc_injection: forced r0=0x{:08X} at return 0x{:08X} for {}'.format(
            _rc_injection_state['return_value'] & 0xFFFFFFFF,
            current_addr & 0xFFFFFFFF,
            _rc_injection_state.get('active_symbol') or '<unknown>',
        ))
    _rc_injection_state['active_symbol'] = None
    _rc_injection_state['active_return_addr'] = None

def _rc_injection_entry_hook(cpu, addr):
    if not _rc_injection_state.get('enabled'):
        return
    current_addr = int(addr) & ~1
    return_addr = int(cpu.GetRegister(14).RawValue) & ~1
    _rc_injection_state['active_symbol'] = _rc_injection_state['entry_symbol_by_addr'].get(current_addr)
    _rc_injection_state['active_return_addr'] = return_addr if return_addr > 0 else None
    if return_addr > 0 and return_addr not in _rc_injection_state['installed_return_hooks']:
        cpu.AddHook(return_addr, _rc_injection_return_hook)
        _rc_injection_state['installed_return_hooks'].add(return_addr)

def ensure_rc_injection_preflight():
    if _rc_injection_state['checked']:
        return {
            'supported': _rc_injection_state['supported'],
            'reason': _rc_injection_state['reason'],
        }
    _rc_injection_state['checked'] = True
    if not _bootloader_elf_path:
        _rc_injection_state['reason'] = 'missing_bootloader_elf'
        return {
            'supported': False,
            'reason': _rc_injection_state['reason'],
        }
    cpu_ref = monitor.Machine['sysbus.cpu']
    resolved = 0
    # Use pre-resolved addresses, falling back to runtime resolution.
    sym_addrs = []
    if _rc_injection_pre_resolved:
        for sym_name, addr in _rc_injection_pre_resolved.items():
            sym_addrs.append((sym_name, addr))
    else:
        for sym_name in _rc_injection_symbols:
            for addr in _resolve_elf_symbol_addresses(sym_name):
                sym_addrs.append((sym_name, addr))
    for sym_name, addr in sym_addrs:
        if addr in _rc_injection_state['entry_symbol_by_addr']:
            continue
        _rc_injection_state['entry_symbol_by_addr'][addr] = sym_name
        cpu_ref.AddHook(addr, _rc_injection_entry_hook)
        resolved += 1
        log('rc_injection: {}=0x{:08X}'.format(sym_name, addr & 0xFFFFFFFF))
    if resolved <= 0:
        _rc_injection_state['reason'] = 'symbol_not_found'
        return {
            'supported': False,
            'reason': _rc_injection_state['reason'],
        }
    _rc_injection_state['supported'] = True
    _rc_injection_state['reason'] = ''
    return {
        'supported': True,
        'reason': '',
    }

def reset_rc_injection_state(enabled=False):
    _rc_injection_state['enabled'] = bool(enabled)
    _rc_injection_state['active_symbol'] = None
    _rc_injection_state['active_return_addr'] = None
    _rc_injection_state['injected'] = False
    _rc_injection_state['injected_symbol'] = None
    _rc_injection_state['injected_return_addr'] = None

# ---------------------------------------------------------------------------
# Verification probes: capture return values from verification-layer helpers
# during instruction-skip runs so we can distinguish "first layer breached"
# from "later layer caught it" deterministically.
# ---------------------------------------------------------------------------
_verification_probes_raw = get_optional_var('verification_probes', '')
_verification_probe_order = []
_verification_probe_state = {
    'entry_templates': {},
    'entry_hook_addrs': set(),
    'installed_return_hooks': set(),
    'active_frames': [],
    'captures': {},
}

def _verification_fmt_u32(value):
    return '0x{:08X}'.format(int(value) & 0xFFFFFFFF)

def _make_verification_probe_capture(cfg):
    return {
        'label': cfg.get('label'),
        'symbol': cfg.get('symbol'),
        'return_register': cfg.get('return_register'),
        'success_value': _verification_fmt_u32(int(cfg.get('success_value', 0))),
        'reached': False,
        'call_count': 0,
        'return_value': None,
        'return_values': [],
        'bypassed': False,
    }

def _load_verification_probe_configs(raw_text):
    if not raw_text:
        return []
    try:
        decoded = base64.b64decode(raw_text).decode('utf-8')
        payload = json.loads(decoded)
    except Exception as e:
        raise RuntimeError('verification_probes: failed to decode payload: {}'.format(e))
    if not isinstance(payload, list):
        raise RuntimeError('verification_probes: expected list payload')
    cfgs = []
    seen_labels = set()
    for i, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise RuntimeError('verification_probes[{}]: expected mapping'.format(i))
        label = str(entry.get('label') or entry.get('symbol') or '').strip()
        symbol = str(entry.get('symbol') or '').strip()
        reg_name = str(entry.get('return_register') or 'r0').strip().lower()
        reg_index = int(entry.get('return_register_index', 0))
        success_value = int(entry.get('success_value', 0))
        if not label or not symbol:
            raise RuntimeError('verification_probes[{}]: label/symbol must be non-empty'.format(i))
        if label in seen_labels:
            raise RuntimeError('verification_probes[{}]: duplicate label {}'.format(i, label))
        seen_labels.add(label)
        cfgs.append({
            'label': label,
            'symbol': symbol,
            'return_register': reg_name,
            'return_register_index': reg_index,
            'success_value': success_value & 0xFFFFFFFF,
        })
    return cfgs

def _verification_probe_return_hook(cpu, addr):
    current_addr = int(addr) & ~1
    active_frames = _verification_probe_state.get('active_frames') or []
    matched_index = None
    matched_frame = None
    for idx in range(len(active_frames) - 1, -1, -1):
        frame = active_frames[idx]
        if frame.get('return_addr') == current_addr:
            matched_index = idx
            matched_frame = frame
            break
    if matched_frame is None:
        return
    try:
        raw_value = int(cpu.GetRegister(int(matched_frame['return_register_index'])).RawValue) & 0xFFFFFFFF
    except Exception:
        raw_value = 0
    label = matched_frame.get('label')
    capture = _verification_probe_state['captures'].get(label)
    if capture is None:
        capture = _make_verification_probe_capture(matched_frame)
        _verification_probe_state['captures'][label] = capture
    capture['reached'] = True
    capture['call_count'] = int(capture.get('call_count') or 0) + 1
    formatted_value = _verification_fmt_u32(raw_value)
    is_success = raw_value == (int(matched_frame.get('success_value', 0)) & 0xFFFFFFFF)
    if capture.get('first_return_value') is None:
        capture['first_return_value'] = formatted_value
        capture['first_bypassed'] = bool(is_success)
    capture['return_value'] = formatted_value
    capture.setdefault('return_values', []).append(formatted_value)
    if is_success:
        capture['bypassed'] = True
    log(
        'verification_probe_return: {} rv={} bypass={}'.format(
            label,
            _verification_fmt_u32(raw_value),
            bool(capture.get('bypassed')),
        )
    )
    try:
        del active_frames[matched_index]
    except Exception:
        pass

def _verification_probe_entry_hook(cpu, addr):
    current_addr = int(addr) & ~1
    templates = _verification_probe_state['entry_templates'].get(current_addr) or []
    if not templates:
        return
    return_addr = int(cpu.GetRegister(14).RawValue) & ~1
    if return_addr <= 0:
        return
    if return_addr not in _verification_probe_state['installed_return_hooks']:
        cpu.AddHook(return_addr, _verification_probe_return_hook)
        _verification_probe_state['installed_return_hooks'].add(return_addr)
    for template in templates:
        frame = {
            'label': template.get('label'),
            'symbol': template.get('symbol'),
            'return_register': template.get('return_register'),
            'return_register_index': int(template.get('return_register_index', 0)),
            'success_value': int(template.get('success_value', 0)) & 0xFFFFFFFF,
            'return_addr': return_addr,
        }
        _verification_probe_state['active_frames'].append(frame)

def reset_verification_probes():
    _verification_probe_state['active_frames'] = []
    captures = {}
    for cfg in _load_verification_probe_configs(_verification_probes_raw):
        captures[cfg['label']] = _make_verification_probe_capture(cfg)
    _verification_probe_state['captures'] = captures

def capture_verification_probe_summary():
    if not _verification_probe_order:
        return None
    probes = {}
    for label in _verification_probe_order:
        capture = _verification_probe_state['captures'].get(label)
        if capture is None:
            continue
        probes[label] = {
            'label': capture.get('label'),
            'symbol': capture.get('symbol'),
            'return_register': capture.get('return_register'),
            'success_value': capture.get('success_value'),
            'reached': bool(capture.get('reached')),
            'call_count': int(capture.get('call_count') or 0),
            'first_return_value': capture.get('first_return_value'),
            'first_bypassed': bool(capture.get('first_bypassed')),
            'return_value': capture.get('return_value'),
            'return_values': list(capture.get('return_values') or []),
            'bypassed': bool(capture.get('first_bypassed')),
            'bypassed_any': bool(capture.get('bypassed')),
        }
    if not probes:
        return None
    ordered = [probes[label] for label in _verification_probe_order if label in probes]
    first = ordered[0] if ordered else None
    later = ordered[1:] if len(ordered) > 1 else []
    classification = 'not_reached'
    defense = 'unknown'
    if first is not None:
        if not first.get('reached'):
            classification = 'first_layer_not_reached'
            defense = 'unknown'
        elif not first.get('first_bypassed'):
            classification = 'first_layer_held'
            defense = 'held'
        elif not later:
            classification = 'single_layer_breached'
            defense = 'defeated'
        elif any(item.get('reached') and not item.get('first_bypassed') for item in later):
            classification = 'first_layer_breached_second_caught'
            defense = 'held'
        elif later and all(item.get('reached') and item.get('first_bypassed') for item in later):
            classification = 'all_layers_breached'
            defense = 'defeated'
        elif any(item.get('first_bypassed') for item in later):
            classification = 'partial_multilayer_bypass'
            defense = 'partial'
        elif any(item.get('reached') for item in later):
            classification = 'first_layer_breached_following_held'
            defense = 'held'
        else:
            classification = 'first_layer_breached_following_not_reached'
            defense = 'unknown'
    bypassed_labels = [label for label, item in probes.items() if item.get('bypassed')]
    full_bypass = classification in ('single_layer_breached', 'all_layers_breached')
    return {
        'probes': probes,
        'classification': classification,
        'defense_in_depth': defense,
        'bypassed_labels': bypassed_labels,
        'layer1_breached': bool(first and first.get('bypassed')),
        'full_bypass': full_bypass,
    }

def merge_verification_probe_signals(signals):
    summary = capture_verification_probe_summary()
    if not summary:
        return
    signals['verification_probes'] = summary.get('probes')
    signals['verification_probe_classification'] = summary.get('classification')
    signals['verification_defense_in_depth'] = summary.get('defense_in_depth')
    signals['verification_bypass_labels'] = summary.get('bypassed_labels')
    signals['verification_bypass_detected'] = bool(summary.get('layer1_breached'))
    signals['verification_full_bypass'] = bool(summary.get('full_bypass'))

_verification_probe_cfgs = _load_verification_probe_configs(_verification_probes_raw)
if _verification_probe_cfgs:
    _verification_probe_order = [cfg['label'] for cfg in _verification_probe_cfgs]
    cpu_ref = monitor.Machine['sysbus.cpu']
    for cfg in _verification_probe_cfgs:
        resolved_addrs = _resolve_elf_symbol_addresses(cfg['symbol'])
        if not resolved_addrs:
            raise RuntimeError(
                'verification_probe: symbol {} not found in ELF'.format(cfg['symbol'])
            )
        for resolved_addr in resolved_addrs:
            templates = _verification_probe_state['entry_templates'].setdefault(resolved_addr, [])
            templates.append(cfg)
            if resolved_addr not in _verification_probe_state['entry_hook_addrs']:
                cpu_ref.AddHook(resolved_addr, _verification_probe_entry_hook)
                _verification_probe_state['entry_hook_addrs'].add(resolved_addr)
            log(
                'verification_probe: {} {}=0x{:08X} {} success={}'.format(
                    cfg['label'],
                    cfg['symbol'],
                    resolved_addr & 0xFFFFFFFF,
                    cfg['return_register'],
                    _verification_fmt_u32(cfg['success_value']),
                )
            )
    reset_verification_probes()

# ---------------------------------------------------------------------------
# Boot register snapshot: capture configurable registers at VTOR detection.
# Format: "0xADDR1=NAME1,0xADDR2=NAME2,..."
# ---------------------------------------------------------------------------
_boot_register_pre_writes_raw = get_optional_var('boot_register_pre_writes', '')
_boot_register_pre_writes = []
if _boot_register_pre_writes_raw:
    for part in _boot_register_pre_writes_raw.split(','):
        part = part.strip()
        if '=' not in part:
            continue
        addr_str, val_str = part.split('=', 1)
        try:
            addr = int(addr_str, 0)
            val = int(val_str, 0)
            _boot_register_pre_writes.append((addr, val))
            log('boot_register_pre_write: 0x{:08X}=0x{:08X}'.format(addr & 0xFFFFFFFF, val & 0xFFFFFFFF))
        except (ValueError, TypeError) as e:
            log('boot_register_pre_write: bad entry {!r} ({})'.format(part, e))

_boot_registers_raw = get_optional_var('boot_registers', '')
_boot_register_defs = []
if _boot_registers_raw:
    for part in _boot_registers_raw.split(','):
        part = part.strip()
        if '=' not in part:
            continue
        addr_str, name = part.split('=', 1)
        try:
            addr = int(addr_str, 0)
            _boot_register_defs.append((addr, name.strip()))
            log('boot_register: {}=0x{:08X}'.format(name.strip(), addr & 0xFFFFFFFF))
        except (ValueError, TypeError) as e:
            log('boot_register: bad entry {!r} ({})'.format(part, e))

def capture_boot_registers():
    if not _boot_register_defs:
        return None
    # Apply pre-writes before reading (e.g., set MPU_RNR to select region 0).
    for addr, val in _boot_register_pre_writes:
        try:
            bus.WriteDoubleWord(addr, val)
        except Exception as e:
            log('boot_register_pre_write failed: 0x{:08X}=0x{:08X} ({})'.format(addr, val, e))
    snapshot = {}
    for addr, name in _boot_register_defs:
        try:
            val = as_int(bus.ReadDoubleWord(addr))
            snapshot[name] = fmt_u32(val)
        except Exception as e:
            snapshot[name] = 'error:{}'.format(e)
    return snapshot

# Reset mode: warm (machine Reset) or cold (full machine recreate).
reset_mode = get_optional_var('reset_mode', 'warm')
if reset_mode not in ('warm', 'cold'):
    reset_mode = 'warm'
durability_model = str(monitor.GetVariable('durability_model')).strip()
writeback_buffer_capacity = str(monitor.GetVariable('writeback_buffer_capacity')).strip()
writeback_barriers = str(monitor.GetVariable('writeback_barriers')).strip()
writeback_erase_flushes = str(monitor.GetVariable('writeback_erase_flushes')).strip().lower() in ('1', 'true', 'yes')

# ---------------------------------------------------------------------------
# Writeback durability layer
#
# When durability_model == 'writeback', writes are modeled as going through a
# volatile write-back buffer before reaching physical flash.  The buffer has
# a finite capacity (in write operations).  At any fault point F, the last
# min(capacity, F) writes are "in buffer" (uncommitted).  Power loss discards
# these uncommitted writes; the faulted flash state only contains committed
# writes.
#
# Barriers: certain addresses can force a flush of the entire buffer,
# modeling explicit cache-flush / write-barrier instructions.
#
# v1 known limitation: reads are NOT intercepted.  The bootloader reads from
# Renode's memory which contains ALL writes (committed + uncommitted).  This
# means the bootloader's execution during Phase 1 is optimistic — it sees
# writes that would not yet be on physical flash.  The writeback model only
# affects the faulted flash snapshot used for Phase 2 recovery boot.  This is
# conservative: if the bootloader survives with the writeback model, it would
# also survive on real hardware where reads might return stale data.  A future
# v2 could intercept reads via a C# overlay peripheral.
# ---------------------------------------------------------------------------

writeback_domains = {}
_writeback_barriers = set()
_writeback_barrier_events = []  # list of dicts recording barrier flush events

if durability_model == 'writeback':
    # Inline erase size calc (effective_page_size not yet defined at this point).
    if backend['kind'] == 'mram':
        _erase_sz = int(backend['data'].WordSize)
    elif backend['kind'] == 'fast':
        try:
            _erase_sz = int(backend['data'].PageSize)
            if _erase_sz <= 0:
                _erase_sz = 4096
        except Exception:
            _erase_sz = 4096
    else:
        _erase_sz = 4096
    _wb_cap = writeback_buffer_capacity
    if _wb_cap == 'auto':
        # Default: one erase sector worth of writes.
        _wb_cap = _erase_sz // write_granularity if _erase_sz > 0 else 4096
    else:
        _wb_cap = int(_wb_cap)
    for _slot_name, (_slot_base, _slot_end) in slot_ranges.items():
        writeback_domains[_slot_name] = {
            'base': _slot_base,
            'size': _slot_end - _slot_base,
            'capacity': _wb_cap,
        }
    # Parse barrier addresses.
    if writeback_barriers:
        for _b_tok in writeback_barriers.split(','):
            _b_tok = _b_tok.strip()
            if _b_tok:
                try:
                    _writeback_barriers.add(int(_b_tok, 0))
                except ValueError:
                    log('writeback: ignoring invalid barrier: {}'.format(_b_tok))
    log('writeback: {} domains initialized (cap={}, barriers={})'.format(
        len(writeback_domains), _wb_cap, len(_writeback_barriers)))


def writeback_active():
    return durability_model == 'writeback' and len(writeback_domains) > 0


def writeback_capacity():
    if not writeback_domains:
        return 4096
    # All domains share the same capacity in v1.
    for d in writeback_domains.values():
        return d['capacity']
    return 4096


def writeback_domain_for_address(bus_addr):
    # Return the domain name containing bus_addr, or None.
    for dname, dinfo in writeback_domains.items():
        if dinfo['base'] <= bus_addr < dinfo['base'] + dinfo['size']:
            return dname
    return None


def writeback_record_barrier_event(write_index, trigger, buffer_len, bus_addr=0):
    # Record a barrier flush event for post-hoc analysis (Tasks 5/6).
    #   trigger: 'address' (write hit barrier addr), 'erase_flush' (erase
    #            forced flush), 'capacity' (buffer overflow eviction)
    domain = writeback_domain_for_address(bus_addr) if bus_addr else None
    _writeback_barrier_events.append({
        'write_index': write_index,
        'trigger': trigger,
        'domain': domain,
        'address': bus_addr,
        'flushed_count': buffer_len,
    })


def writeback_reset_barrier_events():
    _writeback_barrier_events[:] = []


def writeback_simulate_buffer(trace_data, erase_trace, fault_at, flash_base_addr, page_size, record_events=False):
    # Simulate the writeback buffer over a trace to compute dirty state at
    # fault_at.  Returns (committed_indices, uncommitted_buffer, events).
    #
    # committed_indices: set of write_index values that were flushed.
    # uncommitted_buffer: list of (write_index, flash_offset, value) still dirty.
    # events: list of barrier event dicts (only populated when record_events=True).
    cap = writeback_capacity()
    has_barriers = len(_writeback_barriers) > 0

    pending_erases = [(wap, foff, esz if esz > 0 else page_size) for foff, wap, esz in erase_trace]
    pending_erases.sort()
    erase_idx = 0

    buffer = []  # (write_index, flash_offset, value)
    committed = set()
    events = []

    def _flush(trigger, wi, addr):
        for bi, boff, bval in buffer:
            committed.add(bi)
        if record_events and buffer:
            events.append({
                'write_index': wi,
                'trigger': trigger,
                'domain': writeback_domain_for_address(addr) if addr else None,
                'address': addr,
                'flushed_count': len(buffer),
            })
        buffer[:] = []

    for write_idx, flash_off, value in trace_data:
        if write_idx > fault_at:
            break

        # Process erases up to this write.
        while erase_idx < len(pending_erases) and pending_erases[erase_idx][0] < write_idx:
            e_wap, e_off, e_sz = pending_erases[erase_idx]
            if writeback_erase_flushes:
                _flush('erase_flush', e_wap, flash_base_addr + e_off)
            else:
                buffer[:] = [
                    (bi, boff, bval) for bi, boff, bval in buffer
                    if not (e_off <= boff < e_off + e_sz)
                ]
            erase_idx += 1

        if write_idx <= fault_at:
            buffer.append((write_idx, flash_off, value))
            bus_addr = flash_off + flash_base_addr
            if has_barriers and bus_addr in _writeback_barriers:
                _flush('address', write_idx, bus_addr)
            else:
                while len(buffer) > cap:
                    bi, boff, bval = buffer.pop(0)
                    committed.add(bi)
                    if record_events:
                        events.append({
                            'write_index': bi,
                            'trigger': 'capacity',
                            'domain': writeback_domain_for_address(flash_base_addr + boff),
                            'address': flash_base_addr + boff,
                            'flushed_count': 1,
                        })

    return committed, list(buffer), events


def writeback_dirty_state_at(trace_data, erase_trace, fault_at, flash_base_addr, page_size):
    # Compute per-domain dirty write info at a given fault point.
    # Returns a dict: { domain_name: { 'pending': N, 'oldest_wi': int, 'newest_wi': int } }
    if not trace_data:
        return {}
    _, uncommitted, _ = writeback_simulate_buffer(
        trace_data, erase_trace, fault_at, flash_base_addr, page_size,
    )
    per_domain = {}
    for wi, foff, val in uncommitted:
        bus_addr = foff + flash_base_addr
        dname = writeback_domain_for_address(bus_addr) or 'unknown'
        if dname not in per_domain:
            per_domain[dname] = {'pending': 0, 'oldest_wi': wi, 'newest_wi': wi}
        per_domain[dname]['pending'] += 1
        if wi < per_domain[dname]['oldest_wi']:
            per_domain[dname]['oldest_wi'] = wi
        if wi > per_domain[dname]['newest_wi']:
            per_domain[dname]['newest_wi'] = wi
    return per_domain


def writeback_apply_to_trace_snapshot(flash_ref, trace_data, erase_trace, fault_at, flash_base_addr, page_size):
    # Trace-replay variant: replay only committed writes to flash.
    #
    # Returns (writes_applied, fault_injected, fault_address, discarded).
    #
    # In writeback mode, the last `capacity` writes before the fault point
    # are uncommitted (in the volatile buffer).  Only writes that have been
    # flushed -- either by buffer overflow or by hitting a barrier address --
    # are applied to physical flash.
    #
    # Barrier semantics: when a write targets a barrier address, the entire
    # buffer (including that write) is flushed to flash immediately.
    import System

    cap = writeback_capacity()
    has_barriers = len(_writeback_barriers) > 0

    # Pre-sort erases by their write-at-point for interleaving.
    pending_erases = [(wap, foff, esz if esz > 0 else page_size) for foff, wap, esz in erase_trace]
    pending_erases.sort()
    erase_idx = [0]  # mutable container to allow mutation from helper scope

    # Buffer: list of (write_index, flash_offset, value) for uncommitted writes.
    buffer = []
    writes_applied = [0]  # mutable container for same reason
    fault_injected = False
    fault_address = 0

    def _wb_write_word(flash_off, value):
        # Write a single 4-byte word to flash.
        b = System.Array.CreateInstance(System.Byte, 4)
        b[0] = value & 0xFF
        b[1] = (value >> 8) & 0xFF
        b[2] = (value >> 16) & 0xFF
        b[3] = (value >> 24) & 0xFF
        flash_ref.WriteBytes(flash_off, b)

    def _wb_flush_buffer(trigger='address', write_index=0, bus_addr=0):
        # Flush all buffered writes to physical flash.
        cnt = len(buffer)
        for _bi, _boff, _bval in buffer:
            _wb_write_word(_boff, _bval)
            writes_applied[0] += 1
        buffer[:] = []
        if cnt > 0:
            writeback_record_barrier_event(write_index, trigger, cnt, bus_addr)

    def _wb_erase_region(e_off, e_sz, e_wap=0):
        # Apply a single erase to flash, handling buffer interactions.
        if writeback_erase_flushes and buffer:
            _wb_flush_buffer(trigger='erase_flush', write_index=e_wap,
                             bus_addr=flash_base_addr + e_off)
        else:
            # Clear buffered writes that fall in the erased range.
            buffer[:] = [
                (bi, boff, bval) for bi, boff, bval in buffer
                if not (e_off <= boff < e_off + e_sz)
            ]
        erase_buf = System.Array.CreateInstance(System.Byte, e_sz)
        for bi in range(e_sz):
            erase_buf[bi] = 0xFF
        flash_ref.WriteBytes(int(e_off), erase_buf)

    for write_idx, flash_off, value in trace_data:
        if write_idx > fault_at + 1:
            break

        # Apply pending erases whose write-at-point < this write.
        while erase_idx[0] < len(pending_erases) and pending_erases[erase_idx[0]][0] < write_idx:
            e_wap, e_off, e_sz = pending_erases[erase_idx[0]]
            _wb_erase_region(e_off, e_sz, e_wap)
            erase_idx[0] += 1

        if write_idx <= fault_at:
            # Add to buffer.
            buffer.append((write_idx, flash_off, value))

            # Check barrier: if the bus address hits a barrier, flush everything.
            bus_addr = flash_off + flash_base_addr
            if has_barriers and bus_addr in _writeback_barriers:
                _wb_flush_buffer(trigger='address', write_index=write_idx,
                                 bus_addr=bus_addr)
            else:
                # Evict oldest if buffer exceeds capacity.
                while len(buffer) > cap:
                    _bi, _boff, _bval = buffer.pop(0)
                    _wb_write_word(_boff, _bval)
                    writes_applied[0] += 1
                    writeback_record_barrier_event(
                        _bi, 'capacity', 1, flash_base_addr + _boff)
        elif write_idx == fault_at + 1:
            fault_injected = True
            fault_address = flash_off + flash_base_addr
            break

    # Apply any remaining erases up to fault_at.
    while erase_idx[0] < len(pending_erases) and pending_erases[erase_idx[0]][0] <= fault_at:
        e_wap, e_off, e_sz = pending_erases[erase_idx[0]]
        _wb_erase_region(e_off, e_sz, e_wap)
        erase_idx[0] += 1

    # Discard remaining buffer contents -- they represent uncommitted writes
    # lost on power failure.
    discarded = len(buffer)
    buffer[:] = []

    return writes_applied[0], fault_injected, fault_address, discarded


def writeback_strip_uncommitted_from_snapshot(snapshot_bytes, trace_data, erase_trace, fault_at, flash_base_addr, page_size):
    # Execute-mode variant: given a full flash snapshot (with ALL writes
    # applied), revert the uncommitted writes to produce the committed-only
    # state.
    #
    # Returns (committed_snapshot_bytes, uncommitted_count).
    #
    # This works by identifying which writes are uncommitted at fault_at
    # (the last `capacity` writes, unless a barrier forced a flush) and
    # reverting their flash locations to the pre-write value.
    #
    # The pre-write value is determined by replaying the trace up to each
    # uncommitted write and taking the byte values that existed before that
    # write was applied.  For simplicity in v1, we rebuild the committed
    # state from scratch using the trace (same as trace replay), then copy
    # the committed bytes into the snapshot at the affected offsets.
    if not trace_data:
        log('writeback: no trace data for execute-mode snapshot stripping')
        return snapshot_bytes, 0

    cap = writeback_capacity()
    has_barriers = len(_writeback_barriers) > 0

    # Pre-sort erases by their write-at-point.
    pending_erases = [(wap, foff, esz if esz > 0 else page_size) for foff, wap, esz in erase_trace]
    pending_erases.sort()
    erase_idx = 0

    # Simulate the writeback buffer to find which writes are uncommitted.
    buffer = []  # (write_index, flash_offset, value)

    for write_idx, flash_off, value in trace_data:
        if write_idx > fault_at:
            break

        # Process erases.
        while erase_idx < len(pending_erases) and pending_erases[erase_idx][0] < write_idx:
            e_wap, e_off, e_sz = pending_erases[erase_idx]
            if writeback_erase_flushes:
                buffer[:] = []
            else:
                buffer[:] = [
                    (bi, boff, bval) for bi, boff, bval in buffer
                    if not (e_off <= boff < e_off + e_sz)
                ]
            erase_idx += 1

        if write_idx <= fault_at:
            buffer.append((write_idx, flash_off, value))
            bus_addr = flash_off + flash_base_addr
            if has_barriers and bus_addr in _writeback_barriers:
                buffer[:] = []
            else:
                while len(buffer) > cap:
                    buffer.pop(0)

    # `buffer` now contains the uncommitted writes at fault_at.
    if not buffer:
        return snapshot_bytes, 0

    # Build the committed-only flash image by replaying ONLY committed writes
    # from the trace.  We need to know what bytes were at each uncommitted
    # offset before those writes happened.
    #
    # Strategy: rebuild flash from initial state + committed writes only.
    # For each uncommitted write offset, the committed image has the correct
    # pre-write value.  Copy those bytes into the snapshot.
    uncommitted_offsets = set()
    for _bi, boff, _bval in buffer:
        for byte_i in range(4):
            uncommitted_offsets.add(boff + byte_i)

    # Replay committed writes into a mutable copy of the initial image.
    # Start from the snapshot and undo uncommitted writes.
    import struct as _struct
    committed = bytearray(snapshot_bytes)

    # For each uncommitted write, we need to know what the committed state
    # is at that offset.  We reconstruct by replaying from scratch.
    # Build a map of committed values at affected offsets.
    #
    # Simpler approach: replay the entire trace as committed-only into a
    # sparse map, then patch the snapshot.  But that requires knowing the
    # initial flash state.  Since we have the FULL snapshot, we can work
    # backwards: for each uncommitted write, restore the pre-write value.
    #
    # The pre-write value for write W at offset O is whatever was at O
    # just before W executed.  If an earlier write also wrote to O, that
    # earlier write's value is the pre-write value.  If no earlier write
    # touched O, the initial flash value is the pre-write value.
    #
    # For correctness, process uncommitted writes in REVERSE order: the
    # last uncommitted write's pre-write value might be another uncommitted
    # write (if the same address was written multiple times in the buffer).
    # Reversing ensures we peel back layers correctly.

    uncommitted_set = set(bi for bi, _, _ in buffer)

    # Build a map: flash_offset -> list of (write_index, value) for ALL
    # writes to that offset, both committed and uncommitted.
    offset_history = {}
    for write_idx, flash_off, value in trace_data:
        if write_idx > fault_at:
            break
        if flash_off not in offset_history:
            offset_history[flash_off] = []
        offset_history[flash_off].append((write_idx, value))

    # For each uncommitted write, find the committed value at that offset.
    for _bi, boff, _bval in buffer:
        history = offset_history.get(boff, [])
        # Find the latest committed write to this offset (before this uncommitted write).
        committed_value = None
        for hw_idx, hw_val in reversed(history):
            if hw_idx not in uncommitted_set:
                committed_value = hw_val
                break
        if committed_value is not None:
            # Restore to the last committed write's value.
            _struct.pack_into('<I', committed, boff, committed_value)
        else:
            # No committed write to this offset — restore to initial/erased state.
            # MRAM erases to 0x00, NOR flash to 0xFF.
            erase_byte = 0x00 if backend['kind'] == 'mram' else 0xFF
            for byte_i in range(4):
                if boff + byte_i < len(committed):
                    committed[boff + byte_i] = erase_byte

    return bytes(committed), len(buffer)


# Total words in the copy (for state mode).
total_copy_writes = slot_exec_size // write_granularity

# ESP-IDF otadata entry bases (used for post-boot state signals).
OTADATA_ENTRY0_BASE = 0x000F8000
OTADATA_ENTRY1_BASE = 0x000F9000
OTADATA_SEQ_OFF = 0x00
OTADATA_STATE_OFF = 0x18
OTADATA_CRC_OFF = 0x1C

OTADATA_STATE_NAMES = {
    0x00000000: 'NEW',
    0x00000001: 'PENDING_VERIFY',
    0x00000002: 'VALID',
    0x00000003: 'INVALID',
    0x00000004: 'ABORTED',
    0xFFFFFFFF: 'UNDEFINED',
}

def as_int(value):
    try:
        return int(value)
    except Exception:
        try:
            return int(str(value), 0)
        except Exception:
            return 0

def fmt_u32(value):
    return '0x{0:08X}'.format(as_int(value) & 0xFFFFFFFF)

def fmt_hex32(value):
    return '{0:08X}'.format(as_int(value) & 0xFFFFFFFF)

def fmt_u8(value):
    return '0x{0:02X}'.format(as_int(value) & 0xFF)

def normalize_signal_token(value):
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if value is None:
        return ''
    text = str(value).strip()
    if not text:
        return ''
    low = text.lower()
    if low in ('true', 'false'):
        return low
    try:
        parsed = int(text, 0)
    except ValueError:
        return text
    return fmt_u32(parsed)

def to_py_bytes(raw):
    if raw is None:
        return None
    try:
        return bytes(raw)
    except Exception:
        return bytes([int(x) & 0xFF for x in raw])


_state_probe_collect = None


def load_state_probe():
    global _state_probe_collect
    if _state_probe_collect is not None or not state_probe:
        return _state_probe_collect
    with open(state_probe, 'r') as f:
        code = compile(f.read(), state_probe, 'exec')
    probe_ns = {'__builtins__': __builtins__, '__file__': state_probe}
    exec(code, probe_ns)
    collect_fn = probe_ns.get('collect_state')
    if not callable(collect_fn):
        raise RuntimeError(
            'state_probe must define callable collect_state(bus, monitor, context)'
        )
    _state_probe_collect = collect_fn
    log('state_probe: loaded {}'.format(state_probe))
    return _state_probe_collect


def collect_semantic_state(context):
    collect_fn = load_state_probe()
    if collect_fn is None:
        return None
    try:
        state = collect_fn(bus=bus, monitor=monitor, context=context)
    except TypeError:
        state = collect_fn(bus, monitor, context)
    if state is None:
        return None
    if not isinstance(state, dict):
        raise RuntimeError('state_probe collect_state must return dict or None')
    return state


def build_cycle_record(cycle_index, boot_outcome, boot_slot, signals, stop_status=None,
                       fault_injected=False):
    record = {
        'cycle': int(cycle_index),
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'signals': dict(signals) if isinstance(signals, dict) else {},
    }
    if stop_status is not None:
        record['stop_reason'] = stop_status.get('reason')
        record['emulated_s'] = stop_status.get('emulated_s')
        record['elapsed_s'] = stop_status.get('elapsed_s')
        record['iters'] = stop_status.get('iters')
    semantic_state = collect_semantic_state({
        'cycle': int(cycle_index),
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'signals': record['signals'],
        'fault_injected': bool(fault_injected),
        'stage': 'boot_cycle',
    })
    if semantic_state is not None:
        record['semantic_state'] = semantic_state
    return record


def _set_monitor_hook_var(name, value):
    if value is None:
        monitor.Parse('${}=""'.format(name))
        return
    if isinstance(value, bool):
        monitor.Parse('${}={}'.format(name, 'true' if value else 'false'))
        return
    try:
        integer_types = (int, long)
    except NameError:
        integer_types = (int,)
    if isinstance(value, integer_types):
        monitor.Parse('${}={}'.format(name, int(value)))
        return
    monitor.Parse('${}={}'.format(name, json.dumps(str(value))))


def run_boot_cycle_hook(next_cycle_index, cycle_records):
    if not boot_cycle_hook:
        return
    previous_record = cycle_records[-1] if cycle_records else {}
    hook_path = str(boot_cycle_hook).strip()
    if not hook_path:
        return
    _set_monitor_hook_var('boot_cycle_index', int(next_cycle_index))
    _set_monitor_hook_var('boot_cycle_previous_index', int(next_cycle_index) - 1)
    _set_monitor_hook_var('boot_cycle_previous_slot', previous_record.get('boot_slot'))
    _set_monitor_hook_var('boot_cycle_previous_outcome', previous_record.get('boot_outcome'))
    if hook_path.lower().endswith('.py'):
        hook_globals = {
            '__name__': '__tardigrade_boot_cycle_hook__',
            '__file__': hook_path,
            'monitor': monitor,
            'bus': bus,
            'cycle_records': cycle_records,
            'previous_record': previous_record,
            'next_cycle_index': int(next_cycle_index),
            'success_vtor_slot': success_vtor_slot,
        }
        with open(hook_path, 'r') as hook_file:
            source = hook_file.read()
        exec(compile(source, hook_path, 'exec'), hook_globals, hook_globals)
        log('boot_cycle_hook: ran {} before cycle {}'.format(hook_path, next_cycle_index))
        return
    monitor.Parse('include @{}'.format(hook_path))
    log('boot_cycle_hook: included {} before cycle {}'.format(hook_path, next_cycle_index))


class _HookFaultStop(Exception):
    pass


class _FaultInjectingHookBus(object):
    def __init__(self, real_bus, hook_fault_at, hook_fault_type):
        self._bus = real_bus
        self._fault_at = int(hook_fault_at)
        self._fault_type = str(hook_fault_type or 'w')
        self.ops = 0
        self.fired = False
        self.fault_address = 0

    def _mutate_u32(self, value):
        value = as_int(value)
        return (value & 0xFFFF0000) | ((value ^ 0xA5A5) & 0x0000FFFF)

    def _handle_write(self, addr, value, writer):
        addr = as_int(addr)
        value = as_int(value)
        current_idx = self.ops
        self.ops += 1
        if self.fired:
            writer(addr, value)
            return
        if current_idx != self._fault_at:
            writer(addr, value)
            return
        self.fired = True
        self.fault_address = addr
        if self._fault_type == 'k':
            # command_drop: silently discard the write, let hook continue
            return
        if self._fault_type == 'b':
            # bit_corruption: write mutated value, let hook continue
            # (CPU keeps running after a bit flip — only the data is wrong)
            writer(addr, self._mutate_u32(value))
            return
        # power_loss ('w'): halt execution (power died mid-write)
        raise _HookFaultStop()

    def ReadDoubleWord(self, addr):
        return self._bus.ReadDoubleWord(addr)

    def WriteDoubleWord(self, addr, value):
        self._handle_write(addr, value, self._bus.WriteDoubleWord)

    def WriteWord(self, addr, value):
        self._handle_write(addr, value, self._bus.WriteWord)

    def WriteByte(self, addr, value):
        self._handle_write(addr, value, self._bus.WriteByte)

    def WriteQuadWord(self, addr, value):
        self._handle_write(addr, value, self._bus.WriteQuadWord)

    def __getattr__(self, name):
        return getattr(self._bus, name)


def run_boot_cycle_hook_fault(next_cycle_index, cycle_records, hook_fault_at, hook_fault_type):
    previous_record = cycle_records[-1] if cycle_records else {}
    hook_path = str(boot_cycle_hook).strip()
    if not hook_path:
        return {
            'fault_injected': False,
            'skip_reason': 'hook_not_configured',
            'hook_total_ops': 0,
            'hook_max_fault_index': -1,
            'fault_address': 0,
        }
    if not hook_path.lower().endswith('.py'):
        return {
            'fault_injected': False,
            'skip_reason': 'hook_script_not_python',
            'hook_total_ops': 0,
            'hook_max_fault_index': -1,
            'fault_address': 0,
        }
    _set_monitor_hook_var('boot_cycle_index', int(next_cycle_index))
    _set_monitor_hook_var('boot_cycle_previous_index', int(next_cycle_index) - 1)
    _set_monitor_hook_var('boot_cycle_previous_slot', previous_record.get('boot_slot'))
    _set_monitor_hook_var('boot_cycle_previous_outcome', previous_record.get('boot_outcome'))
    hook_bus = _FaultInjectingHookBus(bus, hook_fault_at, hook_fault_type)
    hook_globals = {
        '__name__': '__tardigrade_boot_cycle_hook__',
        '__file__': hook_path,
        'monitor': monitor,
        'bus': hook_bus,
        'cycle_records': cycle_records,
        'previous_record': previous_record,
        'next_cycle_index': int(next_cycle_index),
        'success_vtor_slot': success_vtor_slot,
    }
    with open(hook_path, 'r') as hook_file:
        source = hook_file.read()
    try:
        exec(compile(source, hook_path, 'exec'), hook_globals, hook_globals)
    except _HookFaultStop:
        pass
    except Exception:
        raise
    skip_reason = None
    if not hook_bus.fired:
        skip_reason = 'no_write_at_index'
    return {
        'fault_injected': bool(hook_bus.fired),
        'skip_reason': skip_reason,
        'hook_total_ops': int(hook_bus.ops),
        'hook_max_fault_index': (int(hook_bus.ops) - 1) if hook_bus.ops > 0 else -1,
        'fault_address': int(hook_bus.fault_address),
    }


_boot_cycle_analysis_fn = None


def _load_boot_cycle_analysis():
    global _boot_cycle_analysis_fn
    if _boot_cycle_analysis_fn is not None:
        return _boot_cycle_analysis_fn
    if not repo_root:
        raise RuntimeError('repo_root not set; cannot load scripts/boot_cycle_analysis.py')
    module_path = os.path.join(repo_root, 'scripts', 'boot_cycle_analysis.py')
    namespace = {
        '__name__': '__tardigrade_boot_cycle_analysis__',
        '__file__': module_path,
    }
    with open(module_path, 'r') as module_file:
        source = module_file.read()
    exec(compile(source, module_path, 'exec'), namespace, namespace)
    _boot_cycle_analysis_fn = namespace['analyze_boot_cycles']
    return _boot_cycle_analysis_fn


def analyze_boot_cycles(cycle_records):
    target_slot = success_vtor_slot if success_vtor_slot not in ('', 'any') else None
    return _load_boot_cycle_analysis()(
        cycle_records,
        requested_cycles=int(boot_cycles),
        target_slot=target_slot,
        expected_rollback_at_cycle=expected_rollback_at_cycle,
    )


def _copy_on_boot_vtor_settle_iters():
    """Allow copy-on-boot profiles to settle past transient VTOR handoff.

    Some bootloaders briefly point VTOR at the final exec slot before the
    upgrade/copy cleanup has finished. Stopping on the first capture can
    misclassify the control boot as a completed handoff while trailer/state
    writes are still in flight.
    """
    try:
        is_exec_handoff = success_vtor_slot == 'exec'
        expects_staging_image = bool(expected_exec_sha256) and bool(image_staging_sha256) and (
            expected_exec_sha256 == image_staging_sha256
        )
        return 50 if (is_exec_handoff and expects_staging_image) else 0
    except Exception:
        return 0


def _snapshot_current_flash():
    b = backend
    if b['kind'] == 'otp':
        return b['data'].ReadBytes(0, int(b['data'].Size))
    if b['kind'] == 'mram':
        return b['data'].ReadBytes(0, int(b['data'].Size))
    if b['kind'] == 'fast':
        return b['data'].Flash.ReadBytes(0, int(b['data'].FlashSize))
    return None


def _boot_followup_cycle(cycle_index, fault_injected, label, effective_criteria=None):
    cpu_ref = monitor.Machine['sysbus.cpu']
    reset_nvmc_for_recovery()
    arm_vtor_watchpoint()
    status = run_until_done(
        cpu_ref,
        label='{}_{}'.format(label, cycle_index),
        expect_writes=False,
        zero_writes_is_brick=False,
        wall_timeout=30,
        stop_on_fault=False,
        time_slice=phase2_time_slice,
    )
    disarm_vtor_watchpoint()
    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value,
        pc_value,
        fault_injected=fault_injected,
        enforce_content_criteria=False,
        effective_criteria=effective_criteria,
    )
    signals['followup_cycle'] = int(cycle_index)
    signals['phase_followup_stop_reason'] = status.get('reason')
    signals['phase_followup_emulated_s'] = status.get('emulated_s')
    return build_cycle_record(
        cycle_index,
        boot_outcome,
        boot_slot,
        signals,
        stop_status=status,
        fault_injected=fault_injected,
    )


def _continue_followup_boot_cycles(cycle_records, start_cycle_index, fault_injected, label, effective_criteria=None):
    b = backend
    if b['kind'] == 'slow':
        return cycle_records, {
            'status': 'unsupported_fast_path_required',
            'requested_cycles': int(boot_cycles),
            'completed_cycles': len(cycle_records),
        }, 0

    followup_t0 = _time.time()
    cpu_ref = monitor.Machine['sysbus.cpu']
    if b['kind'] == 'mram':
        flash_size = int(b['data'].Size)
    else:
        flash_size = int(b['data'].FlashSize)

    for cycle_index in range(int(start_cycle_index), int(boot_cycles)):
        run_boot_cycle_hook(cycle_index, cycle_records)
        if b['kind'] == 'mram':
            current_flash = b['data'].ReadBytes(0, flash_size)
        else:
            current_flash = b['data'].Flash.ReadBytes(0, flash_size)
        restore_flash_and_boot(current_flash)
        if _hash_bypass_active:
            apply_hash_bypass()
        cycle_records.append(_boot_followup_cycle(cycle_index, fault_injected, label, effective_criteria=effective_criteria))

    followup_ms = int((_time.time() - followup_t0) * 1000)
    return cycle_records, analyze_boot_cycles(cycle_records), followup_ms


def run_followup_boot_cycles(initial_boot_outcome, initial_boot_slot, initial_signals,
                             initial_status=None, fault_injected=False, label='followup',
                             effective_criteria=None):
    cycle_records = [
        build_cycle_record(
            0,
            initial_boot_outcome,
            initial_boot_slot,
            initial_signals,
            stop_status=initial_status,
            fault_injected=fault_injected,
        )
    ]
    followup_t0 = _time.time()

    if boot_cycles <= 1:
        return None, None, 0

    return _continue_followup_boot_cycles(
        cycle_records,
        start_cycle_index=1,
        fault_injected=fault_injected,
        label=label,
        effective_criteria=effective_criteria,
    )


def run_hook_fault(hook_fault_at, hook_fault_type='w'):
    eff_criteria = get_effective_criteria('h')
    cpu_ref = monitor.Machine['sysbus.cpu']
    fp_t0 = _time.time()

    def skipped_result(reason, actual_writes=0, cycle_records=None, phase1_ms=0, hook_ms=0):
        result = {
            'fault_at': hook_fault_at,
            'fault_requested': hook_fault_at,
            'fault_type': 'h:{}'.format(hook_fault_type),
            'fault_injected': False,
            'fault_address': fmt_u32(0),
            'boot_outcome': 'skipped',
            'boot_slot': None,
            'fault_class': 'skipped',
            'actual_writes': actual_writes,
            'signals': {
                'phase1_ms': int(phase1_ms),
                'phase2_ms': 0,
                'hook_ms': int(hook_ms),
                'followup_ms': 0,
            },
            'hook_fault': {
                'hook_fault_at': int(hook_fault_at),
                'hook_fault_type': hook_fault_type,
                'fault_injected': False,
                'skip_reason': reason,
                'hook_total_ops': 0,
                'hook_max_fault_index': -1,
                'fault_address': fmt_u32(0),
            },
            'skip_reason': reason,
        }
        if cycle_records is not None:
            result['boot_cycles'] = cycle_records
            result['multi_boot_analysis'] = analyze_boot_cycles(cycle_records)
        return result

    if int(boot_cycles) <= 1:
        return skipped_result('boot_cycles_not_enabled')
    if not boot_cycle_hook:
        return skipped_result('hook_not_configured')
    if backend['kind'] == 'slow':
        return skipped_result('unsupported_fast_path_required')

    log('hookfault at={} type={} phase1_setup'.format(hook_fault_at, hook_fault_type))
    restore_phase1_baseline()
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False
    reset_nvmc_for_recovery()
    disarm_fault()

    arm_vtor_watchpoint()
    phase1_status = run_until_done(
        cpu_ref,
        label='hook{}_p1'.format(hook_fault_at),
        stop_on_fault=False,
        max_iters=phase1_max_iters(default_s=4.0),
        wall_timeout=max(120, progress_stall_timeout_s * 3),
    )
    disarm_vtor_watchpoint()
    phase1_ms = int((_time.time() - fp_t0) * 1000)

    actual_writes = get_total_writes()
    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome0, boot_slot0, signals0 = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=False
    )
    signals0['phase1_ms'] = phase1_ms
    signals0['phase2_ms'] = 0
    signals0['hook_ms'] = 0
    signals0['phase1_ops_total'] = actual_writes
    signals0['trace_replay_mode'] = 'hook_fault'
    if phase1_status is not None:
        signals0['phase1_stop_reason'] = phase1_status.get('reason')
        signals0['phase1_emulated_s'] = phase1_status.get('emulated_s')

    cycle_records = [
        build_cycle_record(
            0,
            boot_outcome0,
            boot_slot0,
            signals0,
            stop_status=phase1_status,
            fault_injected=False,
        )
    ]

    hook_t0 = _time.time()
    hook_meta = run_boot_cycle_hook_fault(1, cycle_records, hook_fault_at, hook_fault_type)
    hook_ms = int((_time.time() - hook_t0) * 1000)

    if hook_meta.get('skip_reason') is not None:
        result = skipped_result(
            hook_meta.get('skip_reason'),
            actual_writes=actual_writes,
            cycle_records=cycle_records,
            phase1_ms=phase1_ms,
            hook_ms=hook_ms,
        )
        result['hook_fault']['hook_total_ops'] = int(hook_meta.get('hook_total_ops', 0))
        result['hook_fault']['hook_max_fault_index'] = int(hook_meta.get('hook_max_fault_index', -1))
        result['hook_fault']['fault_address'] = fmt_u32(hook_meta.get('fault_address', 0))
        result['fault_address'] = fmt_u32(hook_meta.get('fault_address', 0))
        return result

    current_flash = _snapshot_current_flash()
    phase2_t0 = _time.time()
    restore_flash_and_boot(current_flash)
    if _hash_bypass_active:
        apply_hash_bypass()
    cycle1_record = _boot_followup_cycle(
        1,
        bool(hook_meta.get('fault_injected')),
        'hook{}_followup'.format(hook_fault_at),
    )
    cycle_records.append(cycle1_record)
    phase2_ms = int((_time.time() - phase2_t0) * 1000)

    if int(boot_cycles) > 2:
        cycle_records, multi_boot_analysis, followup_ms = _continue_followup_boot_cycles(
            cycle_records,
            start_cycle_index=2,
            fault_injected=bool(hook_meta.get('fault_injected')),
            label='hook{}_followup'.format(hook_fault_at),
        )
    else:
        followup_ms = 0
        multi_boot_analysis = analyze_boot_cycles(cycle_records)

    cycle1_signals = cycle1_record.get('signals', {})
    cycle1_signals['phase2_ms'] = int(phase2_ms)
    cycle1_signals['hook_ms'] = int(hook_ms)
    cycle1_signals['followup_ms'] = int(followup_ms)

    result = {
        'fault_at': hook_fault_at,
        'fault_requested': hook_fault_at,
        'fault_type': 'h:{}'.format(hook_fault_type),
        'fault_injected': bool(hook_meta.get('fault_injected')),
        'fault_address': fmt_u32(hook_meta.get('fault_address', 0)),
        'boot_outcome': cycle1_record.get('boot_outcome'),
        'boot_slot': cycle1_record.get('boot_slot'),
        'fault_class': classify_fault_result(
            cycle1_record.get('boot_outcome'),
            cycle1_record.get('boot_slot'),
            cycle1_signals,
            effective_criteria=eff_criteria,
        ),
        'actual_writes': actual_writes,
        'signals': cycle1_signals,
        'boot_cycles': cycle_records,
        'multi_boot_analysis': multi_boot_analysis,
        'hook_fault': {
            'hook_fault_at': int(hook_fault_at),
            'hook_fault_type': hook_fault_type,
            'fault_injected': bool(hook_meta.get('fault_injected')),
            'skip_reason': None,
            'hook_total_ops': int(hook_meta.get('hook_total_ops', 0)),
            'hook_max_fault_index': int(hook_meta.get('hook_max_fault_index', -1)),
            'fault_address': fmt_u32(hook_meta.get('fault_address', 0)),
            'elapsed_s': round(_time.time() - fp_t0, 1),
        },
    }
    if eff_criteria is not None:
        result['effective_success_criteria'] = eff_criteria
    semantic_state = cycle1_record.get('semantic_state')
    if semantic_state is not None:
        result['semantic_state'] = semantic_state
    return result


def _resolve_confirm_function_address():
    # Resolve the confirm function to an address.
    #
    # If the configured value is a hex/integer literal, use it directly.
    # Otherwise treat it as a symbol name and resolve from the firmware ELF
    # (if firmware_elf is set) or the bootloader ELF.
    func = _confirm_cycle_function
    if not func:
        return None
    # Try parsing as integer literal first.
    try:
        return int(func, 0) & 0xFFFFFFFF
    except ValueError:
        pass
    # If firmware_elf is set, resolve from it via nm.
    if _firmware_elf:
        try:
            import subprocess as _sp
            _nm_proc = _sp.Popen(['nm', _firmware_elf], stdout=_sp.PIPE, stderr=_sp.PIPE)
            _nm_stdout, _ = _nm_proc.communicate()
            if hasattr(_nm_stdout, 'decode'):
                _nm_stdout = _nm_stdout.decode('utf-8', errors='replace')
            if _nm_proc.returncode == 0:
                for line in _nm_stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[2] == func:
                        try:
                            addr = int(parts[0], 16)
                            log('confirm_cycle: resolved {} from firmware ELF to 0x{:08X}'.format(func, addr))
                            return addr & 0xFFFFFFFE
                        except ValueError:
                            continue
        except Exception as e:
            log('confirm_cycle: nm on firmware ELF failed: {}'.format(e))
    # Fall back to bootloader ELF symbols.
    addrs = _resolve_elf_symbol_addresses(func)
    if addrs:
        return addrs[0] & 0xFFFFFFFE
    # Try bus.GetSymbolAddress as last resort.
    try:
        return int(bus.GetSymbolAddress(func)) & 0xFFFFFFFE
    except Exception:
        return None


def _evaluate_confirm_assertions(assertions, ratchet_version):
    # Check post-confirm assertions and ratchet version.
    #
    # Returns a dict with confirm_incomplete, rollback_not_ratcheted,
    # metadata_inconsistent_after_confirm flags and details.
    meta = {
        'confirm_incomplete': False,
        'rollback_not_ratcheted': False,
        'metadata_inconsistent_after_confirm': False,
        'assertion_results': [],
    }
    any_failed = False
    for assertion in assertions:
        addr = int(assertion.get('address', '0'), 0) if isinstance(assertion.get('address'), str) else int(assertion.get('address', 0))
        expected = assertion.get('expected')
        label = assertion.get('label', '0x{:08X}'.format(addr))
        actual = as_int(bus.ReadDoubleWord(addr))
        if isinstance(expected, list):
            passed = actual in [int(str(e), 0) if isinstance(e, str) else int(e) for e in expected]
        else:
            expected_int = int(str(expected), 0) if isinstance(expected, str) else int(expected)
            passed = actual == expected_int
        entry = {
            'address': '0x{:08X}'.format(addr),
            'expected': expected,
            'actual': '0x{:08X}'.format(actual),
            'label': label,
            'passed': passed,
        }
        meta['assertion_results'].append(entry)
        if not passed:
            any_failed = True
    if any_failed:
        meta['metadata_inconsistent_after_confirm'] = True
    if ratchet_version is not None:
        # Check the expected_ratchet_version against assertion results.
        # Compares the configured value directly against each assertion's
        # actual read-back.  An assertion matches if its label contains
        # 'version' or 'ratchet' (case-insensitive).  Profiles MUST use
        # one of these substrings in the label of the ratchet-version
        # assertion for this check to engage.
        ratchet_ok = False
        for ar in meta['assertion_results']:
            lbl = str(ar.get('label', '')).lower()
            if 'version' in lbl or 'ratchet' in lbl:
                actual_int = int(ar['actual'], 16) if isinstance(ar['actual'], str) else int(ar['actual'])
                if actual_int == ratchet_version:
                    ratchet_ok = True
                    break
        if not ratchet_ok and meta['assertion_results']:
            meta['rollback_not_ratcheted'] = True
    return meta


def run_confirm_cycle_fault(cc_fault_at, cc_fault_type='w'):
    # Fault injection during the confirm phase.
    #
    # The confirm_function address is resolved as a validation gate (must
    # exist in the ELF) but is not used as a CPU breakpoint.  Instead,
    # fault injection targets the boot_cycle_hook's NVM writes.
    #
    # 1. Boot normally (no faults) to reach firmware.
    # 2. Run the boot_cycle_hook with a fault-injecting bus that
    #    interrupts the write at index cc_fault_at.
    # 3. Reboot and check metadata assertions.
    eff_criteria = get_effective_criteria('cc')
    cpu_ref = monitor.Machine['sysbus.cpu']
    fp_t0 = _time.time()

    def skipped_result(reason, cycle_records=None, phase1_ms=0):
        result = {
            'fault_at': cc_fault_at,
            'fault_requested': cc_fault_at,
            'fault_type': 'cc:{}'.format(cc_fault_type),
            'fault_injected': False,
            'fault_address': fmt_u32(0),
            'boot_outcome': 'skipped',
            'boot_slot': None,
            'fault_class': 'skipped',
            'actual_writes': 0,
            'signals': {
                'phase1_ms': int(phase1_ms),
                'phase2_ms': 0,
                'confirm_ms': 0,
                'followup_ms': 0,
            },
            'confirm_cycle': {
                'cc_fault_at': int(cc_fault_at),
                'cc_fault_type': cc_fault_type,
                'fault_injected': False,
                'skip_reason': reason,
                'confirm_incomplete': False,
                'rollback_not_ratcheted': False,
                'metadata_inconsistent_after_confirm': False,
            },
            'skip_reason': reason,
        }
        if cycle_records is not None:
            result['boot_cycles'] = cycle_records
            result['multi_boot_analysis'] = analyze_boot_cycles(cycle_records)
        return result

    if not _confirm_cycle_enabled:
        return skipped_result('confirm_cycle_not_enabled')
    if not _confirm_cycle_function:
        return skipped_result('confirm_function_not_configured')
    if backend['kind'] == 'slow':
        return skipped_result('unsupported_fast_path_required')

    confirm_addr = _resolve_confirm_function_address()
    if confirm_addr is None:
        return skipped_result('confirm_function_not_resolved')

    log('confirm_cycle at={} type={} confirm_fn=0x{:08X}'.format(
        cc_fault_at, cc_fault_type, confirm_addr))

    # Phase 1: Normal boot (no faults).
    restore_phase1_baseline()
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False
    reset_nvmc_for_recovery()
    disarm_fault()

    arm_vtor_watchpoint()
    phase1_status = run_until_done(
        cpu_ref,
        label='cc{}_p1'.format(cc_fault_at),
        stop_on_fault=False,
        max_iters=phase1_max_iters(default_s=4.0),
        wall_timeout=max(120, progress_stall_timeout_s * 3),
    )
    disarm_vtor_watchpoint()
    phase1_ms = int((_time.time() - fp_t0) * 1000)

    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome0, boot_slot0, signals0 = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=False
    )
    signals0['phase1_ms'] = phase1_ms
    signals0['confirm_ms'] = 0

    cycle_records = [
        build_cycle_record(0, boot_outcome0, boot_slot0, signals0,
                           stop_status=phase1_status, fault_injected=False)
    ]

    if boot_outcome0 != 'success':
        return skipped_result('phase1_boot_failed', cycle_records=cycle_records,
                              phase1_ms=phase1_ms)

    # Phase 2: Run confirm function with fault injection.
    # Use the hook fault bus to intercept writes during confirm.
    confirm_t0 = _time.time()
    hook_bus = _FaultInjectingHookBus(bus, cc_fault_at, cc_fault_type)

    # Simulate the confirm function's NVM writes using the hook bus.
    # If a boot_cycle_hook is configured, run it with the fault-injecting bus.
    if boot_cycle_hook:
        hook_path = str(boot_cycle_hook).strip()
        if hook_path and hook_path.lower().endswith('.py'):
            _set_monitor_hook_var('boot_cycle_index', 1)
            _set_monitor_hook_var('boot_cycle_previous_index', 0)
            _set_monitor_hook_var('boot_cycle_previous_slot', boot_slot0)
            _set_monitor_hook_var('boot_cycle_previous_outcome', boot_outcome0)
            hook_globals = {
                '__name__': '__tardigrade_boot_cycle_hook__',
                '__file__': hook_path,
                'monitor': monitor,
                'bus': hook_bus,
                'cycle_records': cycle_records,
                'previous_record': cycle_records[-1],
                'next_cycle_index': 1,
                'success_vtor_slot': success_vtor_slot,
            }
            with open(hook_path, 'r') as hook_file:
                source = hook_file.read()
            try:
                exec(compile(source, hook_path, 'exec'), hook_globals, hook_globals)
            except _HookFaultStop:
                pass

    confirm_ms = int((_time.time() - confirm_t0) * 1000)

    cc_meta = {
        'cc_fault_at': int(cc_fault_at),
        'cc_fault_type': cc_fault_type,
        'fault_injected': bool(hook_bus.fired),
        'skip_reason': None,
        'confirm_total_ops': int(hook_bus.ops),
        'confirm_max_fault_index': (int(hook_bus.ops) - 1) if hook_bus.ops > 0 else -1,
        'fault_address': fmt_u32(hook_bus.fault_address),
    }

    if not hook_bus.fired and cc_fault_at >= hook_bus.ops:
        cc_meta['skip_reason'] = 'no_write_at_index'
        cc_meta['confirm_incomplete'] = True

    # Phase 3: Reboot and evaluate.
    current_flash = _snapshot_current_flash()
    phase3_t0 = _time.time()
    restore_flash_and_boot(current_flash)
    if _hash_bypass_active:
        apply_hash_bypass()
    cycle1_record = _boot_followup_cycle(
        1,
        bool(hook_bus.fired),
        'cc{}_followup'.format(cc_fault_at),
    )
    cycle_records.append(cycle1_record)
    phase3_ms = int((_time.time() - phase3_t0) * 1000)

    # Additional boot cycles for convergence testing.
    if int(boot_cycles) > 2:
        cycle_records, multi_boot_analysis, followup_ms = _continue_followup_boot_cycles(
            cycle_records,
            start_cycle_index=2,
            fault_injected=bool(hook_bus.fired),
            label='cc{}_followup'.format(cc_fault_at),
        )
    else:
        followup_ms = 0
        multi_boot_analysis = analyze_boot_cycles(cycle_records)

    # Evaluate post-confirm assertions.
    confirm_eval = _evaluate_confirm_assertions(
        _confirm_cycle_assertions,
        _confirm_cycle_ratchet_version,
    )
    cc_meta['confirm_incomplete'] = bool(
        cc_meta.get('confirm_incomplete')
        or (hook_bus.fired and confirm_eval.get('metadata_inconsistent_after_confirm'))
    )
    cc_meta['rollback_not_ratcheted'] = confirm_eval.get('rollback_not_ratcheted', False)
    cc_meta['metadata_inconsistent_after_confirm'] = confirm_eval.get(
        'metadata_inconsistent_after_confirm', False
    )
    cc_meta['assertion_results'] = confirm_eval.get('assertion_results', [])

    cycle1_signals = cycle1_record.get('signals', {})
    cycle1_signals['phase2_ms'] = int(phase3_ms)
    cycle1_signals['confirm_ms'] = int(confirm_ms)
    cycle1_signals['followup_ms'] = int(followup_ms)

    result = {
        'fault_at': cc_fault_at,
        'fault_requested': cc_fault_at,
        'fault_type': 'cc:{}'.format(cc_fault_type),
        'fault_injected': bool(hook_bus.fired),
        'fault_address': fmt_u32(hook_bus.fault_address),
        'boot_outcome': cycle1_record.get('boot_outcome'),
        'boot_slot': cycle1_record.get('boot_slot'),
        'fault_class': classify_fault_result(
            cycle1_record.get('boot_outcome'),
            cycle1_record.get('boot_slot'),
            cycle1_signals,
            effective_criteria=eff_criteria,
        ),
        'actual_writes': get_total_writes(),
        'signals': cycle1_signals,
        'boot_cycles': cycle_records,
        'multi_boot_analysis': multi_boot_analysis,
        'confirm_cycle': cc_meta,
    }
    if eff_criteria is not None:
        result['effective_success_criteria'] = eff_criteria
    semantic_state = cycle1_record.get('semantic_state')
    if semantic_state is not None:
        result['semantic_state'] = semantic_state
    return result


def effective_page_size():
    b = backend
    if b['kind'] == 'mram':
        return int(b['data'].WordSize)
    if b['kind'] == 'fast':
        try:
            p = int(b['data'].PageSize)
            if p > 0:
                return p
        except Exception:
            pass
    return 4096

def flash_geometry():
    slot_bases = [int(slot_exec_base), int(slot_staging_base)]
    slot_ends = [
        int(slot_exec_base) + int(slot_exec_size),
        int(slot_staging_base) + int(slot_staging_size),
    ]
    if slot_tertiary_base is not None and slot_tertiary_size is not None:
        slot_bases.append(int(slot_tertiary_base))
        slot_ends.append(int(slot_tertiary_base) + int(slot_tertiary_size))
    if slot_recovery_base is not None and slot_recovery_size is not None:
        slot_bases.append(int(slot_recovery_base))
        slot_ends.append(int(slot_recovery_base) + int(slot_recovery_size))
    b = backend
    if b['kind'] == 'mram':
        # Derive MRAM bus base by aligning lowest slot address down to
        # MRAM size boundary (MRAM size is always a power of two).
        mram_size = int(b['data'].Size)
        lowest_slot = min(slot_bases)
        base = lowest_slot & ~(mram_size - 1)
        return base, mram_size
    if b['kind'] == 'fast':
        return int(b['data'].FlashBaseAddress), int(b['data'].FlashSize)
    try:
        return int(slot_exec_base), int(b['data'].Nvm.Size)
    except Exception:
        flash_base = min(slot_bases)
        flash_end = max(slot_ends)
        return flash_base, flash_end - flash_base

def read_flash_span(start_addr, size, snapshot_bytes=None):
    if size <= 0:
        return b''
    flash_base, flash_size = flash_geometry()
    rel = int(start_addr) - int(flash_base)
    if rel < 0 or rel >= flash_size:
        return b''
    max_len = min(int(size), flash_size - rel)
    if max_len <= 0:
        return b''
    if snapshot_bytes is not None:
        return bytes(snapshot_bytes[rel:rel + max_len])
    b = backend
    if b['kind'] == 'mram':
        return to_py_bytes(b['data'].ReadBytes(rel, max_len))
    if b['kind'] == 'fast':
        return to_py_bytes(b['data'].Flash.ReadBytes(rel, max_len))
    return bytes([as_int(bus.ReadByte(start_addr + i)) & 0xFF for i in range(max_len)])

def region_dump(region_bytes, region_addr):
    import base64
    import hashlib
    non_ff = []
    for i, b in enumerate(region_bytes):
        if b != 0xFF:
            non_ff.append({
                'offset': i,
                'address': fmt_u32(region_addr + i),
                'value': fmt_u8(b),
            })
    non_ff_preview = non_ff[:512]
    return {
        'address': fmt_u32(region_addr),
        'size': len(region_bytes),
        'all_ff': len(non_ff) == 0,
        'non_ff_count': len(non_ff),
        'non_ff_preview': non_ff_preview,
        'non_ff_preview_truncated': len(non_ff) > len(non_ff_preview),
        'sha256': hashlib.sha256(region_bytes).hexdigest(),
        'raw_base64': base64.b64encode(region_bytes).decode('ascii'),
    }

def evaluate_slot_header(slot_base, slot_size, header_bytes):
    if len(header_bytes) < 8:
        return {
            'valid': False,
            'reason': 'header_too_small',
        }
    sp = struct.unpack_from('<I', header_bytes, 0)[0]
    reset_vector = struct.unpack_from('<I', header_bytes, 4)[0]
    reset_pc = reset_vector & ~1
    valid = (
        sram_start <= sp <= sram_end
        and (reset_vector & 1) == 1
        and slot_base <= reset_pc < (slot_base + slot_size)
    )
    return {
        'valid': bool(valid),
        'sp': fmt_u32(sp),
        'reset_vector': fmt_u32(reset_vector),
        'reset_pc': fmt_u32(reset_pc),
    }

def summarize_slot_sectors(slot_bytes, sector_size):
    sector_size = max(1, int(sector_size))
    sectors = []
    erased = []
    non_erased = []
    count = (len(slot_bytes) + sector_size - 1) // sector_size
    for idx in range(count):
        off = idx * sector_size
        chunk = slot_bytes[off:off + sector_size]
        is_erased = all(b == 0xFF for b in chunk)
        sectors.append({
            'index': idx,
            'all_ff': bool(is_erased),
        })
        if is_erased:
            erased.append(idx)
        else:
            non_erased.append(idx)
    return {
        'count': count,
        'sector_size': sector_size,
        'erased_indices': erased,
        'non_erased_indices': non_erased,
        'map': sectors,
    }

def decode_trailer_flags(slot_base, slot_size, trailer_bytes):
    trailer_len = len(trailer_bytes)
    if trailer_len < 32:
        return {'available': False}
    trailer_base = slot_base + slot_size - trailer_len
    copy_done = struct.unpack_from('<I', trailer_bytes, trailer_len - 32)[0]
    image_ok = struct.unpack_from('<I', trailer_bytes, trailer_len - 24)[0]
    swap_info = struct.unpack_from('<I', trailer_bytes, trailer_len - 20)[0]
    magic_words = [
        struct.unpack_from('<I', trailer_bytes, trailer_len - 16 + i * 4)[0]
        for i in range(4)
    ]
    non_ff_status = []
    status_end = max(0, trailer_len - 32)
    for i in range(status_end):
        b = trailer_bytes[i]
        if b != 0xFF:
            non_ff_status.append({
                'offset': i,
                'address': fmt_u32(trailer_base + i),
                'value': fmt_u8(b),
            })
    status_preview = non_ff_status[:512]
    return {
        'available': True,
        'copy_done': fmt_u32(copy_done),
        'image_ok': fmt_u32(image_ok),
        'swap_info': fmt_u32(swap_info),
        'magic': [fmt_u32(m) for m in magic_words],
        'status_non_ff_count': len(non_ff_status),
        'status_non_ff_preview': status_preview,
        'status_non_ff_preview_truncated': len(non_ff_status) > len(status_preview),
    }

def build_slot_partition_dump(slot_name, slot_base, slot_size, snapshot_bytes=None):
    slot_data = read_flash_span(slot_base, slot_size, snapshot_bytes=snapshot_bytes)
    page_size = effective_page_size()
    header_len = min(max(32, postmortem_dump_header_bytes), slot_size)
    trailer_len = min(page_size, slot_size)
    header = slot_data[:header_len]
    trailer = slot_data[max(0, slot_size - trailer_len):slot_size]
    return {
        'name': slot_name,
        'base': fmt_u32(slot_base),
        'size': slot_size,
        'sector_summary': summarize_slot_sectors(slot_data, page_size),
        'header': region_dump(header, slot_base),
        'header_eval': evaluate_slot_header(slot_base, slot_size, header),
        'trailer': region_dump(trailer, slot_base + slot_size - trailer_len),
        'trailer_flags': decode_trailer_flags(slot_base, slot_size, trailer),
    }

def build_postmortem_partition_dump(snapshot_bytes=None, source='live_flash'):
    slots_dump = {}
    for slot_name, (slot_base, slot_end) in slot_ranges.items():
        slots_dump[slot_name] = build_slot_partition_dump(
            slot_name,
            slot_base,
            slot_end - slot_base,
            snapshot_bytes=snapshot_bytes,
        )
    return {
        'source': source,
        'header_region_bytes': postmortem_dump_header_bytes,
        'sector_size': effective_page_size(),
        'slots': slots_dump,
    }

def parse_otadata_expect(raw):
    parsed = {}
    if not raw:
        return parsed
    for pair in raw.split(';'):
        pair = pair.strip()
        if not pair or '=' not in pair:
            continue
        key, values_raw = pair.split('=', 1)
        key = key.strip()
        if not key:
            continue
        values = []
        for item in values_raw.split('|'):
            token = normalize_signal_token(item)
            if token:
                values.append(token)
        if values:
            parsed[key] = values
    return parsed

success_otadata_expect = parse_otadata_expect(success_otadata_expect_raw)
_base_phase_context['success_criteria']['otadata_expect'] = dict(success_otadata_expect)

def read_otadata_entry(base_addr):
    seq = as_int(bus.ReadDoubleWord(base_addr + OTADATA_SEQ_OFF))
    state_raw = as_int(bus.ReadDoubleWord(base_addr + OTADATA_STATE_OFF))
    crc_raw = as_int(bus.ReadDoubleWord(base_addr + OTADATA_CRC_OFF))
    state_name = OTADATA_STATE_NAMES.get(state_raw, 'UNKNOWN')
    return {
        'seq_raw': seq & 0xFFFFFFFF,
        'state_raw': state_raw & 0xFFFFFFFF,
        'state_name': state_name,
        'crc_raw': crc_raw & 0xFFFFFFFF,
    }

def select_otadata_active_entry(entry0, entry1):
    # Mirrors ESP-IDF's "higher seq wins" behavior for observability.
    seq0 = entry0['seq_raw']
    seq1 = entry1['seq_raw']
    if seq0 == seq1:
        return 'tie'
    return 'entry0' if seq0 > seq1 else 'entry1'

def collect_otadata_signals():
    # Best-effort only; some profiles may not model ESP-IDF otadata.
    try:
        e0 = read_otadata_entry(OTADATA_ENTRY0_BASE)
        e1 = read_otadata_entry(OTADATA_ENTRY1_BASE)
    except Exception:
        return {
            'otadata_available': False,
        }

    digest = '{0}|{1}'.format(
        '{}:{}:{}'.format(
            fmt_hex32(e0['seq_raw']),
            fmt_hex32(e0['state_raw']),
            fmt_hex32(e0['crc_raw']),
        ),
        '{}:{}:{}'.format(
            fmt_hex32(e1['seq_raw']),
            fmt_hex32(e1['state_raw']),
            fmt_hex32(e1['crc_raw']),
        ),
    )

    return {
        'otadata_available': True,
        'otadata_active_entry': select_otadata_active_entry(e0, e1),
        'otadata_digest': digest,
        'otadata0_seq': fmt_u32(e0['seq_raw']),
        'otadata0_state': fmt_u32(e0['state_raw']),
        'otadata0_state_name': e0['state_name'],
        'otadata0_crc': fmt_u32(e0['crc_raw']),
        'otadata1_seq': fmt_u32(e1['seq_raw']),
        'otadata1_state': fmt_u32(e1['state_raw']),
        'otadata1_state_name': e1['state_name'],
        'otadata1_crc': fmt_u32(e1['crc_raw']),
    }

# ---------------------------------------------------------------------------
# Write tracking abstraction — dispatches on backend['kind'].
# ---------------------------------------------------------------------------
def get_total_writes():
    b = backend
    if b['kind'] == 'otp':
        return int(b['data'].TotalBlows)
    if b['kind'] == 'mram':
        return int(b['data'].TotalWordWrites)
    if b['kind'] == 'fast':
        return int(b['data'].TotalWordWrites)
    return int(b['data'].Nvm.TotalWordWrites)

def get_total_commands():
    ctrl = backend['controller']
    if ctrl is None:
        return 0
    try:
        return int(ctrl.CommandExecutions)
    except Exception:
        return 0

def get_total_erases():
    b = backend
    if b['kind'] == 'otp':
        return 0  # OTP has no page erases.
    if b['kind'] == 'mram':
        return 0  # MRAM has no page erases.
    if b['kind'] == 'fast':
        return int(b['data'].TotalPageErases)
    return 0  # Slow path doesn't track erases.

def arm_fault(absolute_write_index, write_fault_mode=0):
    b = backend
    if b['kind'] == 'otp':
        b['data'].BlowFaultMode = write_fault_mode
        b['data'].FaultAtBlow = absolute_write_index
        b['data'].BlowFaultFired = False
    elif b['kind'] == 'mram':
        b['data'].WriteFaultMode = write_fault_mode
        b['data'].FaultAtWordWrite = absolute_write_index
        b['data'].LastFaultInjected = False
        b['data'].FaultEverFired = False
        b['data'].DriverErrorFired = False
    elif b['kind'] == 'fast':
        b['data'].WriteFaultMode = write_fault_mode
        b['data'].FaultAtWordWrite = absolute_write_index
        b['data'].FaultFired = False
        b['data'].DriverErrorFired = False
    else:
        b['data'].Nvm.WriteFaultMode = write_fault_mode
        b['data'].Nvm.FaultAtWordWrite = absolute_write_index
        b['data'].Nvm.FaultEverFired = False
        b['data'].Nvm.DriverErrorFired = False

def arm_controller_fault(absolute_command_index, command_fault_mode=1):
    ctrl = backend['controller']
    if ctrl is None:
        return
    try:
        ctrl.FaultAtCommandExecution = absolute_command_index
        ctrl.CommandFaultMode = command_fault_mode
        ctrl.CommandFaultFired = False
    except Exception:
        pass

def arm_erase_fault(absolute_erase_index, erase_fault_mode=0):
    b = backend
    if b['kind'] == 'otp':
        log('WARNING: erase fault requested on OTP backend (no page erases)')
        return  # OTP has no page erases.
    if b['kind'] == 'mram':
        log('WARNING: erase fault requested on MRAM backend (no page erases)')
        return  # MRAM has no page erases.
    elif b['kind'] == 'fast':
        b['data'].EraseFaultMode = erase_fault_mode
        b['data'].FaultAtPageErase = absolute_erase_index
        b['data'].EraseFaultFired = False

def disarm_fault():
    b = backend
    if b['kind'] == 'otp':
        b['data'].FaultAtBlow = _DISARM_SENTINEL
    elif b['kind'] == 'mram':
        b['data'].FaultAtWordWrite = _DISARM_SENTINEL
    elif b['kind'] == 'fast':
        b['data'].FaultAtWordWrite = _DISARM_SENTINEL
        b['data'].FaultAtPageErase = _DISARM_SENTINEL
    else:
        b['data'].Nvm.FaultAtWordWrite = _DISARM_SENTINEL
    disarm_controller_fault()

def disarm_write_fault():
    b = backend
    if b['kind'] == 'otp':
        b['data'].FaultAtBlow = _DISARM_SENTINEL
    elif b['kind'] == 'mram':
        b['data'].FaultAtWordWrite = _DISARM_SENTINEL
    elif b['kind'] == 'fast':
        b['data'].FaultAtWordWrite = _DISARM_SENTINEL
    else:
        b['data'].Nvm.FaultAtWordWrite = _DISARM_SENTINEL

def disarm_erase_fault():
    b = backend
    if b['kind'] == 'otp':
        pass  # OTP has no page erases.
    elif b['kind'] == 'mram':
        pass  # MRAM has no page erases.
    elif b['kind'] == 'fast':
        b['data'].FaultAtPageErase = _DISARM_SENTINEL

_OTP_WIRE_CODES = frozenset(('op', 'os', 'od', 'oo'))

def arm_otp_fault(absolute_blow_index, blow_fault_mode=0):
    otp_dev = backend.get('otp')
    if otp_dev is None:
        return
    otp_dev.BlowFaultMode = blow_fault_mode
    otp_dev.FaultAtBlow = absolute_blow_index
    otp_dev.BlowFaultFired = False

def disarm_otp_fault():
    otp_dev = backend.get('otp')
    if otp_dev is None:
        return
    otp_dev.FaultAtBlow = _DISARM_SENTINEL

def was_otp_fault_injected():
    otp_dev = backend.get('otp')
    if otp_dev is None:
        return False
    return bool(otp_dev.BlowFaultFired)

def get_total_otp_blows():
    otp_dev = backend.get('otp')
    if otp_dev is None:
        return 0
    return int(otp_dev.TotalBlows)

def disarm_controller_fault():
    ctrl = backend['controller']
    if ctrl is None:
        return
    try:
        ctrl.FaultAtCommandExecution = _DISARM_SENTINEL
        ctrl.CommandFaultMode = 0
        ctrl.CommandFaultFired = False
    except Exception:
        pass

def was_fault_injected():
    b = backend
    if b['kind'] == 'otp':
        return bool(b['data'].BlowFaultFired) or was_controller_fault_injected()
    if b['kind'] == 'mram':
        # FaultEverFired is a sticky flag set when any write fault fires
        # and never cleared by subsequent writes or disarm_fault().
        return bool(b['data'].FaultEverFired) or was_controller_fault_injected()
    if b['kind'] == 'fast':
        return bool(b['data'].FaultFired) or bool(b['data'].EraseFaultFired) or was_controller_fault_injected()
    return bool(b['data'].Nvm.FaultEverFired) or was_controller_fault_injected()

def fault_requires_immediate_stop():
    b = backend
    if b['kind'] == 'otp':
        return bool(b['data'].BlowFaultFired) or was_controller_fault_injected()
    if b['kind'] == 'mram':
        return (bool(b['data'].FaultEverFired) and int(getattr(b['data'], 'WriteFaultMode', 0)) == 0) or was_controller_fault_injected()
    if b['kind'] == 'fast':
        try:
            return bool(b['data'].FaultRequiresImmediateStop) or was_controller_fault_injected()
        except Exception:
            write_fault_fired = bool(b['data'].FaultFired)
            write_fault_mode = int(getattr(b['data'], 'WriteFaultMode', 0))
            return bool(b['data'].EraseFaultFired) or (write_fault_fired and write_fault_mode == 0) or was_controller_fault_injected()
    return (bool(b['data'].Nvm.FaultEverFired) and int(getattr(b['data'].Nvm, 'WriteFaultMode', 0)) == 0) or was_controller_fault_injected()

def was_write_fault_injected():
    b = backend
    if b['kind'] == 'otp':
        return bool(b['data'].BlowFaultFired)
    if b['kind'] == 'mram':
        return bool(b['data'].FaultEverFired)
    if b['kind'] == 'fast':
        return bool(b['data'].FaultFired)
    return bool(b['data'].Nvm.FaultEverFired)

def driver_error_flag_set():
    b = backend
    if b['kind'] == 'mram':
        try:
            return bool(b['data'].DriverErrorFired)
        except Exception:
            return False
    if b['kind'] == 'fast':
        try:
            return bool(b['data'].DriverErrorFired)
        except Exception:
            return False
    try:
        return bool(b['data'].Nvm.DriverErrorFired)
    except Exception:
        return False

def was_erase_fault_injected():
    b = backend
    if b['kind'] == 'otp':
        return False  # OTP has no page erases.
    if b['kind'] == 'mram':
        return False  # MRAM has no page erases.
    if b['kind'] == 'fast':
        return bool(b['data'].EraseFaultFired)
    return False

def was_controller_fault_injected():
    ctrl = backend['controller']
    if ctrl is None:
        return False
    try:
        return bool(ctrl.CommandFaultFired)
    except Exception:
        return False

def get_last_write_address():
    b = backend
    if b['kind'] == 'mram':
        return 0  # MRAMMemory does not track fault address.
    if b['kind'] == 'fast':
        try:
            return int(b['data'].LastFaultAddress)
        except Exception:
            return 0
    return int(b['data'].Nvm.LastWriteAddress)

def get_last_command_address():
    ctrl = backend['controller']
    if ctrl is None:
        return 0
    try:
        return int(ctrl.LastCommandAddress)
    except Exception:
        return 0

# ---------------------------------------------------------------------------
# I2C fault injection helpers — dispatch on backend['i2c_proxy'].
# ---------------------------------------------------------------------------

def get_total_i2c_transactions():
    proxy = backend.get('i2c_proxy')
    if proxy is None:
        return 0
    try:
        return int(proxy.TotalTransactions)
    except Exception:
        return 0

def arm_i2c_fault(absolute_transaction_index, i2c_fault_type=1, i2c_fault_seed=0):
    proxy = backend.get('i2c_proxy')
    if proxy is None:
        return
    try:
        proxy.FaultAtTransaction = absolute_transaction_index
        proxy.FaultType = i2c_fault_type
        proxy.FaultSeed = i2c_fault_seed
        proxy.FaultFired = False
    except Exception:
        pass

def disarm_i2c_fault():
    proxy = backend.get('i2c_proxy')
    if proxy is None:
        return
    try:
        proxy.FaultAtTransaction = _DISARM_SENTINEL
        proxy.FaultType = 0
        proxy.FaultFired = False
    except Exception:
        pass

def was_i2c_fault_injected():
    proxy = backend.get('i2c_proxy')
    if proxy is None:
        return False
    try:
        return bool(proxy.FaultFired)
    except Exception:
        return False

def ensure_i2c_fault_preflight():
    return {
        'supported': backend.get('supports_i2c_fault', False),
        'reason': backend.get('i2c_fault_reason', 'no_i2c_fault_peripheral'),
    }

# I2C wire code to I2CFaultProxy FaultType integer mapping.
_I2C_WIRE_CODE_TO_FAULT_TYPE = {
    'in': 1,  # NACK
    'it': 2,  # Timeout
    'ib': 3,  # BitFlip
    'ic': 4,  # TruncatedResponse
    'iw': 5,  # WrongAddress
}

def prime_bootloader_entry():
    # Some Cortex-M platforms do not reliably restore SP/PC from the loaded
    # bootloader image after machine Reset. Re-prime the core from the vector
    # table so execution starts from the bootloader entry on the next RunFor.
    try:
        initial_sp = as_int(bus.ReadDoubleWord(int(bootloader_entry)))
        initial_pc = as_int(bus.ReadDoubleWord(int(bootloader_entry) + 4))
        cpu_ref = monitor.Machine['sysbus.cpu']
        for cpu_name in ('cpu', 'sysbus.cpu'):
            try:
                monitor.Parse('{} VectorTableOffset 0x{:08X}'.format(cpu_name, int(bootloader_entry)))
                if initial_sp != 0:
                    monitor.Parse('{} SP 0x{:08X}'.format(cpu_name, initial_sp))
                if initial_pc != 0:
                    monitor.Parse('{} PC 0x{:08X}'.format(cpu_name, initial_pc))
                break
            except Exception:
                continue
        try:
            cpu_ref.IsHalted = False
        except Exception:
            pass
        try:
            log('prime_boot: entry={} sp={} pc={} cpu_pc={} vtor={}'.format(
                fmt_u32(int(bootloader_entry)),
                fmt_u32(initial_sp),
                fmt_u32(initial_pc),
                fmt_u32(as_int(cpu_ref.GetRegisterUnsafe(15))),
                fmt_u32(as_int(bus.ReadDoubleWord(0xE000ED08))),
            ))
        except Exception:
            pass
    except Exception:
        pass

def apply_pre_boot_state():
    if pre_boot_bin:
        with open(pre_boot_bin, 'rb') as f:
            pbs_data = f.read()
        for i in range(0, len(pbs_data), 8):
            addr, val = struct.unpack_from('<II', pbs_data, i)
            bus.WriteDoubleWord(addr, val)
    if setup_script:
        monitor.Parse('include @' + setup_script)
    prime_bootloader_entry()


def _apply_pre_boot_entries(entries):
    if not entries:
        prime_bootloader_entry()
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        bus.WriteDoubleWord(int(entry.get('address', 0)), int(entry.get('u32', 0)))
    prime_bootloader_entry()

def apply_partial_pre_boot_state(max_writes, fault_type='w'):
    if not pre_boot_bin:
        return (0, 0, False)
    with open(pre_boot_bin, 'rb') as f:
        pbs_data = f.read()
    total_entries = len(pbs_data) // 8
    applied = 0
    fault_address = 0
    fault_injected = False
    for i in range(total_entries):
        addr, val = struct.unpack_from('<II', pbs_data, i * 8)
        if i < max_writes:
            bus.WriteDoubleWord(addr, val)
            applied += 1
        elif i == max_writes:
            fault_address = addr
            fault_injected = True
            if fault_type == 'b':
                corrupted = (val & 0xFFFF0000) | ((val ^ 0xA5A5) & 0x0000FFFF)
                bus.WriteDoubleWord(addr, corrupted)
                applied += 1
            break
        else:
            break
    return (applied, fault_address, fault_injected)

def restore_hw_init():
    # Restore hardware init values cleared by machine Reset.
    # These are nRF52 NVMC/FICR registers needed for correct operation.
    # Skip for MRAM path — these addresses overlap MRAM and would corrupt data.
    if backend['kind'] == 'mram':
        return
    bus.WriteDoubleWord(0x10000010, 0x1000)
    bus.WriteDoubleWord(0x10000014, 0x100)
    bus.WriteDoubleWord(0x40000100, 0x1)
    bus.WriteDoubleWord(0x40000418, 0x10001)

def reset_nvmc_for_sweep():
    # Reset NVM counters and prepare for fault-injected run.
    b = backend
    if b['kind'] == 'mram':
        b['data'].TotalWordWrites = 0
        b['data'].LastFaultInjected = False
        b['data'].FaultEverFired = False
        b['data'].WriteFaultMode = 0
        b['data'].DriverErrorFired = False
    elif b['kind'] == 'fast':
        # Keep default as full diff for index precision, but allow profile/CLI
        # overrides for performance experiments.
        b['data'].DiffLookahead = sweep_diff_lookahead
        b['data'].TotalWordWrites = 0
        b['data'].TotalPageErases = 0
        b['data'].WriteFaultMode = 0
        b['data'].EraseFaultMode = 0
        b['data'].FaultFired = False
        b['data'].DriverErrorFired = False
        b['data'].EraseFaultFired = False
        b['data'].LastFaultAddress = 0
        b['data'].FaultFlashSnapshot = None
        # Shadow scanning: enable for NRF52-style controllers (WEN batches
        # multiple writes, needs diff to count them).  Skip for STM32F4-style
        # controllers where each PG deactivation = exactly 1 word write —
        # shadow scanning adds 1MB ReadBytes per write with no accuracy benefit.
        if getattr(b['data'], 'PerWriteAccurate', False):
            b['data'].SkipShadowScan = True
        else:
            b['data'].SkipShadowScan = False
            b['data'].InvalidateShadow()
        b['data'].PassthroughMode = False
    else:
        b['data'].Nvm.TotalWordWrites = 0
        b['data'].Nvm.FaultEverFired = False
        b['data'].Nvm.WriteFaultMode = 0
        b['data'].Nvm.DriverErrorFired = False
    # Reset controller fault state on all backends — command_drop can be
    # used with any backend via the separate nvm_controller field.
    disarm_controller_fault()
    # Reset I2C fault state.
    disarm_i2c_fault()

def reset_nvmc_for_recovery():
    # Reset NVM for recovery boot: no write counting needed, fast mode.
    b = backend
    if b['kind'] == 'mram':
        b['data'].TotalWordWrites = 0
        b['data'].LastFaultInjected = False
        b['data'].FaultEverFired = False
        b['data'].WriteFaultMode = 0
        b['data'].DriverErrorFired = False
        disarm_fault()
        return
    if b['kind'] == 'fast':
        b['data'].DiffLookahead = 32
        b['data'].TotalWordWrites = 0
        b['data'].TotalPageErases = 0
        b['data'].WriteFaultMode = 0
        b['data'].EraseFaultMode = 0
        b['data'].FaultFired = False
        b['data'].DriverErrorFired = False
        b['data'].EraseFaultFired = False
        b['data'].LastFaultAddress = 0
        # Skip shadow scanning during recovery boot — just count PG transitions
        # for progress tracking. Avoids O(flash_size) ReadBytes per write.
        b['data'].SkipShadowScan = True
        b['data'].PassthroughMode = True
        disarm_fault()
    else:
        b['data'].Nvm.TotalWordWrites = 0
        b['data'].Nvm.FaultEverFired = False
        b['data'].Nvm.WriteFaultMode = 0
        b['data'].Nvm.DriverErrorFired = False
        disarm_fault()
    # Reset I2C fault state for recovery boot.
    disarm_i2c_fault()


def get_machine_snapshot_path(kind):
    cache_dir = os.path.join(os.path.dirname(result_file), '.machine_snapshots')
    if not os.path.isdir(cache_dir):
        os.makedirs(cache_dir)
    return os.path.join(cache_dir, '{}.save'.format(kind))


def save_machine_snapshot(path):
    monitor.Parse('Save @{}'.format(path))


def load_machine_snapshot(path):
    monitor.Parse('Load @{}'.format(path))
    monitor.Parse('mach set {}'.format(_machine_selector))
    refresh_runtime_handles()


def restore_initial_flash_cache():
    try:
        monitor.Parse('machine Pause')
    except:
        pass
    b = backend
    if _cached_initial_flash is not None and b['kind'] == 'mram':
        b['data'].WriteBytes(0, _cached_initial_flash, 0, len(_cached_initial_flash))
        return True
    if _cached_initial_flash is not None and b['kind'] == 'fast':
        b['data'].Flash.WriteBytes(0, _cached_initial_flash)
        return True
    reload_images()
    apply_pre_boot_state()
    cache_initial_flash()
    return False


def prepare_clean_phase1_state():
    monitor.Parse('machine Reset')
    monitor.Parse('machine Pause')
    needs_pre_boot = restore_initial_flash_cache()
    if needs_pre_boot:
        apply_pre_boot_state()
    if _hash_bypass_active:
        apply_hash_bypass()


def restore_phase1_baseline():
    global _cached_phase1_snapshot_path
    if update_sequence_enabled:
        ensure_update_sequence_fault_baseline()
        _apply_phase_context(update_sequence_fault_phase)
        restore_flash_and_boot(_cached_update_sequence_fault_flash)
        _apply_update_phase_pre_boot(update_sequence_fault_phase)
        if _hash_bypass_active:
            apply_hash_bypass()
        return
    if not enable_machine_snapshots:
        prepare_clean_phase1_state()
        return
    if _cached_phase1_snapshot_path is None:
        _cached_phase1_snapshot_path = get_machine_snapshot_path('phase1_baseline')
        prepare_clean_phase1_state()
        save_machine_snapshot(_cached_phase1_snapshot_path)
        return
    load_machine_snapshot(_cached_phase1_snapshot_path)


def prepare_recovery_shell_state():
    if reset_mode == 'cold':
        prepare_cold_reset()
    else:
        monitor.Parse('machine Reset')
    monitor.Parse('machine Pause')
    _bus_load_elf(bootloader_elf)
    restore_hw_init()
    prime_bootloader_entry()

def prepare_cold_reset():
    # Cold reset: save NVM, destroy and recreate machine, restore NVM.
    # This exercises the full hardware init path, catching issues that
    # warm reset (which preserves peripheral state) would miss.
    b = backend
    if b['kind'] == 'mram':
        nvm_size = int(b['data'].Size)
        nvm_snapshot = b['data'].ReadBytes(0, nvm_size)
    else:
        flash_ref = b['data'].Flash
        nvm_size = int(flash_ref.Size)
        nvm_snapshot = flash_ref.ReadBytes(0, nvm_size)
    # Warm reset is the best we can do in Renode without full machine
    # teardown/recreate (which would invalidate all peripheral references).
    # The NVM save/restore ensures we at least clear any cached peripheral
    # state that survives a normal reset.
    monitor.Parse('machine Reset')
    # Restore the NVM contents that were saved before reset.
    if b['kind'] == 'mram':
        b['data'].WriteBytes(0, nvm_snapshot, 0, len(nvm_snapshot))
    else:
        flash_ref = b['data'].Flash
        flash_ref.WriteBytes(0, nvm_snapshot)

def restore_flash_and_boot(saved_flash):
    # Common pattern: restore a cached post-reset machine shell, then overlay
    # the faulted flash snapshot.  This preserves semantics while avoiding
    # repeated full reset/ELF reload work on every point.
    global _cached_recovery_snapshot_path
    if not enable_machine_snapshots:
        prepare_recovery_shell_state()
    else:
        if _cached_recovery_snapshot_path is None:
            _cached_recovery_snapshot_path = get_machine_snapshot_path('recovery_shell')
            prepare_recovery_shell_state()
            save_machine_snapshot(_cached_recovery_snapshot_path)
        else:
            load_machine_snapshot(_cached_recovery_snapshot_path)
    b = backend
    if b['kind'] == 'mram':
        # MRAMMemory may or may not survive machine Reset depending on
        # vtable dispatch.  Always restore to be safe.
        b['data'].WriteBytes(0, saved_flash, 0, len(saved_flash))
    else:
        flash_ref = b['data'].Flash
        flash_ref.WriteBytes(0, saved_flash)
    # Do NOT re-run setup_script here.  The faulted snapshot is the
    # ground-truth state for the recovery boot — re-running setup would
    # overwrite it with clean data and mask the fault.

def _load_images_mapping(images_map):
    if not images_map:
        return
    for slot_name, image_path in images_map.items():
        if not image_path:
            continue
        base_addr = slot_load_addresses.get(str(slot_name))
        if base_addr is None:
            raise RuntimeError('unknown slot in update_sequence images: {}'.format(slot_name))
        _bus_load_binary(str(image_path), int(base_addr))


def reload_images_from_map(images_map):
    # Restore flash/NVM to a clean erased state, then load the requested images.
    # Ensure machine is paused before loading binaries.
    try:
        monitor.Parse('machine Pause')
    except:
        pass
    b = backend
    if b['kind'] == 'mram':
        # MRAM erased state: fill with EraseFill byte (typically 0x00).
        mram_size = int(b['data'].Size)
        import System
        erase_fill = int(b['data'].EraseFill)
        erased = System.Array.CreateInstance(System.Byte, mram_size)
        if erase_fill != 0:
            for i in range(mram_size):
                erased[i] = erase_fill
        b['data'].WriteBytes(0, erased, 0, mram_size)
    elif b['kind'] == 'fast':
        # Fast path: fill MappedMemory with 0xFF (erased state).
        # Use page-size chunks via NVMC ERASEPAGE for efficient fill.
        flash_size = int(b['data'].FlashSize)
        flash_base = int(b['data'].FlashBaseAddress)
        page_size = int(b['data'].PageSize)
        flash_ref = b['data'].Flash
        # Create one page of 0xFF, reuse for all pages.
        import System
        global _cached_erase_page
        if _cached_erase_page is None or len(_cached_erase_page) != page_size:
            _cached_erase_page = System.Array.CreateInstance(System.Byte, page_size)
            for i in range(page_size):
                _cached_erase_page[i] = 0xFF
        erase_page = _cached_erase_page
        for offset in range(0, flash_size, page_size):
            remaining = min(page_size, flash_size - offset)
            if remaining == page_size:
                flash_ref.WriteBytes(offset, erase_page)
            else:
                partial = System.Array.CreateInstance(System.Byte, remaining)
                for i in range(remaining):
                    partial[i] = 0xFF
                flash_ref.WriteBytes(offset, partial)
    else:
        # Slow path: use NVMemory.EraseSector.
        nvm_size = int(b['data'].Nvm.Size)
        sector = 4096
        for offset in range(0, nvm_size, sector):
            chunk = min(sector, nvm_size - offset)
            b['data'].Nvm.EraseSector(offset, chunk)
    _bus_load_elf(bootloader_elf)
    _load_images_mapping(images_map)


def _fill_slot_region(base, size, pattern):
    """Fill a memory region with a byte pattern."""
    import System
    fill_arr = System.Array.CreateInstance(System.Byte, size)
    if pattern != 0:
        for i in range(size):
            fill_arr[i] = pattern
    b = backend
    if b['kind'] == 'mram':
        periph_offset = base - nvm_base_address
        b['data'].WriteBytes(periph_offset, fill_arr, 0, size)
    elif b['kind'] == 'fast':
        flash_ref = b['data'].Flash
        flash_off = base - int(b['data'].FlashBaseAddress)
        flash_ref.WriteBytes(flash_off, fill_arr)
    else:
        word = (pattern << 24) | (pattern << 16) | (pattern << 8) | pattern
        for off in range(0, size, 4):
            bus.WriteDoubleWord(base + off, word)


def _apply_residual_image():
    # Simulate residual data in a slot after an in-place update.
    #
    # Two modes:
    #   1. fill_pattern WITHOUT prior_image: fill the full slot with the
    #      pattern, then load the actual image on top.  Models a full slot
    #      erase (0xFF for flash, 0x00 for MRAM) before the new write.
    #   2. prior_image with optional fill_pattern: load the prior (larger)
    #      image first, then load the actual (smaller) image on top.  Tail
    #      bytes from the prior image remain beyond the actual image boundary.
    #      If fill_pattern is also set, fill the residual tail from
    #      actual_image_size to prior_image_size with the pattern.
    if not residual_image_enabled:
        return
    target_base = slot_load_addresses.get(residual_image_slot)
    if target_base is None:
        log('residual_image: unknown slot {}'.format(residual_image_slot))
        return

    actual_image_path = {
        'exec': image_exec_path,
        'staging': image_staging_path,
        'tertiary': image_tertiary_path,
        'recovery': image_recovery_path,
    }.get(residual_image_slot, '')

    if residual_image_prior:
        # Mode 2: load prior image first, then actual on top.
        _bus_load_binary(residual_image_prior, target_base)
        if actual_image_path:
            _bus_load_binary(actual_image_path, target_base)
        # If fill_pattern is set, fill the residual tail between the actual
        # image end and the prior image end.
        if residual_image_fill is not None and actual_image_path:
            actual_size = os.path.getsize(actual_image_path)
            prior_size = os.path.getsize(residual_image_prior)
            if prior_size > actual_size:
                tail_base = target_base + actual_size
                tail_size = prior_size - actual_size
                _fill_slot_region(tail_base, tail_size, residual_image_fill)
                log('residual_image: filled residual tail 0x{:08X}+0x{:X} with 0x{:02X}'.format(
                    tail_base, tail_size, residual_image_fill))
        log('residual_image: loaded prior image at slot {} (0x{:08X}), then overwrote with actual'.format(
            residual_image_slot, target_base))
    elif residual_image_fill is not None:
        # Mode 1: fill full slot, then load actual on top.
        slot_cfg = slot_ranges.get(residual_image_slot)
        if slot_cfg:
            s_lo, s_hi = slot_cfg
            _fill_slot_region(s_lo, s_hi - s_lo, residual_image_fill)
        if actual_image_path:
            _bus_load_binary(actual_image_path, target_base)
        log('residual_image: filled slot {} (0x{:08X}) with 0x{:02X}, then loaded actual'.format(
            residual_image_slot, target_base, residual_image_fill))


def reload_images():
    reload_images_from_map({
        'staging': image_staging_path,
        'exec': image_exec_path,
        'tertiary': image_tertiary_path,
        'recovery': image_recovery_path,
    })
    _apply_residual_image()


def _prepare_update_phase_start_state(phase, phase_index):
    try:
        monitor.Parse('machine Pause')
    except:
        pass
    if int(phase_index) == 0:
        reload_images_from_map(phase.get('start_images', {}))
    else:
        _load_images_mapping(phase.get('images', {}))
    _apply_update_phase_pre_boot(phase)
    if _hash_bypass_active:
        apply_hash_bypass()


def _apply_update_phase_pre_boot(phase):
    phase_setup_script = str(phase.get('setup_script', '') or '').strip()
    if phase_setup_script:
        monitor.Parse('include @' + phase_setup_script)
    _apply_pre_boot_entries(phase.get('pre_boot_state', []))


def _run_clean_update_phase(phase, phase_index):
    _apply_phase_context(phase)
    _prepare_update_phase_start_state(phase, phase_index)
    phase_name = str(phase.get('name', 'phase_{}'.format(phase_index)))
    phase_start_flash = _snapshot_current_flash()
    restore_flash_and_boot(phase_start_flash)
    _apply_update_phase_pre_boot(phase)
    if _hash_bypass_active:
        apply_hash_bypass()
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False
    reset_nvmc_for_recovery()
    disarm_fault()

    arm_vtor_watchpoint()
    wall_timeout = max(120, progress_stall_timeout_s * 3)
    max_iters = phase1_max_iters(default_s=4.0)
    status = run_until_done(
        cpu_ref,
        label='update_phase_{}_p1'.format(phase_name),
        stop_on_fault=False,
        max_iters=max_iters,
        wall_timeout=wall_timeout,
        vtor_settle_iters=_copy_on_boot_vtor_settle_iters(),
    )
    disarm_vtor_watchpoint()
    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value,
        pc_value,
        fault_injected=False,
    )
    cycle_records, multi_boot_analysis, _followup_ms = run_followup_boot_cycles(
        boot_outcome,
        boot_slot,
        signals,
        initial_status=status,
        fault_injected=False,
        label='update_phase_{}_followup'.format(phase_name),
    )
    final_outcome = boot_outcome
    final_slot = boot_slot
    if cycle_records:
        last_cycle = cycle_records[-1]
        final_outcome = last_cycle.get('boot_outcome', final_outcome)
        final_slot = last_cycle.get('boot_slot', final_slot)

    # Content verification: followup cycles skip content criteria
    # (enforce_content_criteria=False) so a rollback could be hidden behind
    # a passing VTOR check.  Re-verify the final flash state with full
    # content criteria to catch this.
    if final_outcome == 'success' and success_image_hash and expected_exec_sha256:
        hash_slot = success_image_hash_slot if success_image_hash_slot not in ('', 'any') else final_slot
        actual_hash = compute_slot_hash(hash_slot)
        if actual_hash != expected_exec_sha256:
            log('update_phase {}: content verification FAILED after followup cycles '
                '(expected={}, actual={})'.format(phase_name, expected_exec_sha256[:16], actual_hash[:16]))
            final_outcome = 'wrong_image'

    return {
        'phase_name': phase_name,
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'final_outcome': final_outcome,
        'final_slot': final_slot,
        'stop_reason': status.get('reason') if status is not None else None,
        'multi_boot_analysis': multi_boot_analysis,
    }


def ensure_update_sequence_fault_baseline():
    global _cached_update_sequence_fault_flash
    if not update_sequence_enabled:
        return False
    if _cached_update_sequence_fault_flash is not None:
        return True
    for idx, phase in enumerate(update_sequence_phases):
        phase_name = str(phase.get('name', 'phase_{}'.format(idx)))
        if bool(phase.get('fault_injection')):
            _apply_phase_context(phase)
            _prepare_update_phase_start_state(phase, idx)
            _cached_update_sequence_fault_flash = _snapshot_current_flash()
            log('update_sequence: cached fault baseline for phase {}'.format(phase_name))
            return True
        clean_result = _run_clean_update_phase(phase, idx)
        log('update_sequence: clean phase {} boot={} final={}'.format(
            phase_name,
            clean_result.get('boot_outcome'),
            clean_result.get('final_outcome'),
        ))
        if clean_result.get('final_outcome') != 'success':
            raise RuntimeError(
                "update_sequence clean phase '{}' failed (boot_outcome={}, final_outcome={}, stop_reason={})".format(
                    phase_name,
                    clean_result.get('boot_outcome'),
                    clean_result.get('final_outcome'),
                    clean_result.get('stop_reason'),
                )
            )
    raise RuntimeError('update_sequence fault baseline could not be prepared')

def cache_initial_flash():
    # Snapshot flash after reload_images + apply_pre_boot_state so subsequent
    # fault points can restore with a single bulk WriteBytes instead of
    # 244 page erases + 3 binary loads.
    global _cached_initial_flash
    b = backend
    if b['kind'] == 'mram':
        _cached_initial_flash = b['data'].ReadBytes(0, int(b['data'].Size))
    elif b['kind'] == 'fast':
        flash_ref = b['data'].Flash
        _cached_initial_flash = flash_ref.ReadBytes(0, int(b['data'].FlashSize))

def reload_images_cached():
    # Restore flash from cached snapshot if available; otherwise fall back
    # to full reload_images + apply_pre_boot_state and cache the result.
    if update_sequence_enabled:
        ensure_update_sequence_fault_baseline()
        try:
            monitor.Parse('machine Pause')
        except:
            pass
        b = backend
        if b['kind'] == 'mram':
            b['data'].WriteBytes(0, _cached_update_sequence_fault_flash, 0, len(_cached_update_sequence_fault_flash))
        elif b['kind'] == 'fast':
            b['data'].Flash.WriteBytes(0, _cached_update_sequence_fault_flash)
        _apply_phase_context(update_sequence_fault_phase)
        return
    global _cached_initial_flash
    try:
        monitor.Parse('machine Pause')
    except:
        pass
    b = backend
    if _cached_initial_flash is not None and b['kind'] == 'mram':
        b['data'].WriteBytes(0, _cached_initial_flash, 0, len(_cached_initial_flash))
    elif _cached_initial_flash is not None and b['kind'] == 'fast':
        b['data'].Flash.WriteBytes(0, _cached_initial_flash)
    else:
        reload_images()
        apply_pre_boot_state()
        cache_initial_flash()

def compute_slot_hash(slot_name='exec'):
    # Compute SHA-256 of the selected slot image data (excluding trailer page).
    # Bootloaders modify trailer fields during swap, so the full-slot hash
    # won't match the original binary. Hashing only the data portion
    # (everything except the last page) avoids this problem.
    import hashlib
    slot_key = str(slot_name or 'exec')
    if slot_key not in slot_ranges:
        slot_key = 'exec'
    slot_base, slot_end = slot_ranges[slot_key]
    slot_size = slot_end - slot_base
    page_size = 4096
    data_size = slot_size - page_size
    if data_size <= 0:
        data_size = slot_size
    b = backend
    if b['kind'] == 'mram':
        mram_base, _ = flash_geometry()
        offset = slot_base - mram_base
        data = bytes(b['data'].ReadBytes(offset, data_size))
    elif b['kind'] == 'fast':
        flash_ref = b['data'].Flash
        flash_base_addr = int(b['data'].FlashBaseAddress)
        offset = slot_base - flash_base_addr
        data = bytes(flash_ref.ReadBytes(offset, data_size))
    else:
        chunks = []
        for addr in range(slot_base, slot_base + data_size, 4):
            chunks.append(struct.pack('<I', as_int(bus.ReadDoubleWord(addr))))
        data = b''.join(chunks)
    return hashlib.sha256(data).hexdigest()

def compute_exec_slot_hash():
    return compute_slot_hash('exec')

def evaluate_boot_outcome(vtor_value, pc_value, fault_injected=False, enforce_content_criteria=True, effective_criteria=None, p2_status=None):
    # Shared boot outcome evaluation for all execution modes.
    # When effective_criteria is provided, use its values instead of globals.
    eff_vtor_slot = success_vtor_slot
    eff_image_hash = success_image_hash
    eff_image_hash_slot = success_image_hash_slot
    if effective_criteria is not None:
        eff_vtor_slot = effective_criteria.get('vtor_slot', success_vtor_slot)
        eff_image_hash = effective_criteria.get('image_hash', success_image_hash)
        eff_image_hash_slot = effective_criteria.get('image_hash_slot', success_image_hash_slot)

    # Prioritize 'sticky' VTOR captured by watchpoint during the run.
    actual_vtor = vtor_value
    if sticky_vtor['captured']:
        actual_vtor = sticky_vtor['value']

    # ARMv6-M VTOR: bits [31:7] are the offset, bits [6:0] reserved.
    # Minimum alignment is 128 bytes (2^7).
    vtor_aligned = (actual_vtor % 128 == 0)

    boot_slot = None
    for sn, (s_lo, s_hi) in slot_ranges.items():
        if s_lo <= actual_vtor < s_hi:
            boot_slot = sn
            break

    vtor_in_known_slot = boot_slot is not None

    vtor_ok = not bool(eff_vtor_slot)
    if eff_vtor_slot == 'any':
        # Any defined slot is acceptable.
        vtor_ok = vtor_in_known_slot
    elif eff_vtor_slot and eff_vtor_slot in slot_ranges:
        s_lo, s_hi = slot_ranges[eff_vtor_slot]
        vtor_ok = (s_lo <= actual_vtor < s_hi)

    pc_ok = True
    if success_pc_slot and success_pc_slot in slot_ranges:
        s_lo, s_hi = slot_ranges[success_pc_slot]
        pc_ok = (s_lo <= (pc_value & ~1) < s_hi)
        # If VTOR was captured but PC is now 0 (e.g. crash/reset),
        # treat the VTOR jump as proof of execution attempt.
        if sticky_vtor['captured'] and pc_value == 0:
            pc_ok = True

    marker_ok = True
    hash_result = None
    actual_marker_val = 0
    actual_hash = None
    if enforce_content_criteria:
        if eff_image_hash:
            enforce_hash = True
            if eff_image_hash_slot and eff_image_hash_slot != 'any':
                enforce_hash = (boot_slot == eff_image_hash_slot)
            if enforce_hash:
                hash_slot = eff_image_hash_slot if eff_image_hash_slot not in ('', 'any') else boot_slot
                actual_hash = compute_slot_hash(hash_slot)
                if actual_hash == image_exec_sha256:
                    hash_result = 'exec_image'
                elif actual_hash == image_staging_sha256:
                    hash_result = 'staging_image'
                elif expected_exec_sha256 and actual_hash == expected_exec_sha256:
                    hash_result = 'expected_image'
                else:
                    hash_result = 'unknown'
                # Success = exec slot matches the expected post-operation hash.
                if expected_exec_sha256:
                    marker_ok = (actual_hash == expected_exec_sha256)
                else:
                    # No expected hash: any known image is success.
                    marker_ok = (hash_result != 'unknown')
            else:
                hash_result = 'skipped'
        elif success_marker_addr != 0:
            actual_marker_val = as_int(bus.ReadDoubleWord(success_marker_addr))
            marker_ok = (actual_marker_val == success_marker_value)

    # Anti-rollback: when enabled, a boot that lands on the old (pre-upgrade)
    # image is a rollback failure even if other checks pass. Detected via
    # image_hash: after upgrade, exec should contain the staging image.
    rollback_ok = True
    if security_anti_rollback and enforce_content_criteria and hash_result is not None:
        expected_is_exec = bool(expected_exec_sha256) and expected_exec_sha256 == image_exec_sha256
        if expected_exec_sha256 and (not expected_is_exec) and hash_result == 'exec_image':
            rollback_ok = False
        elif not expected_exec_sha256 and hash_result == 'exec_image' and image_staging_sha256:
            rollback_ok = False

    signals = {
        'vtor': fmt_u32(actual_vtor),
        'vtor_final': fmt_u32(vtor_value),
        'vtor_sticky': sticky_vtor['captured'],
        'execution_observed': vtor_in_known_slot,
        'vtor_aligned': vtor_aligned,
        'vtor_ok': vtor_ok,
        'pc': fmt_u32(pc_value),
        'pc_ok': pc_ok,
        'marker_ok': marker_ok,
        'marker_actual': fmt_u32(actual_marker_val),
    }
    if hash_result is not None:
        signals['image_hash_match'] = hash_result
    if eff_image_hash_slot:
        signals['image_hash_slot'] = eff_image_hash_slot
    if security_anti_rollback:
        signals['anti_rollback_ok'] = rollback_ok
    signals.update(collect_otadata_signals())

    otadata_expect_ok = True
    otadata_mismatches = []
    enforce_otadata_expect = False
    if enforce_content_criteria:
        enforce_otadata_expect = bool(success_otadata_expect)
        if success_otadata_expect_scope == 'control':
            enforce_otadata_expect = not bool(fault_injected)

    if enforce_otadata_expect:
        for key, expected_values in success_otadata_expect.items():
            actual = normalize_signal_token(signals.get(key))
            if actual not in expected_values:
                otadata_expect_ok = False
                otadata_mismatches.append(
                    '{}:{}->{}'.format(
                        key,
                        actual if actual else 'missing',
                        '|'.join(expected_values),
                    )
                )
    signals['otadata_expect_scope'] = success_otadata_expect_scope
    signals['otadata_expect_enforced'] = enforce_otadata_expect
    signals['otadata_expect_ok'] = otadata_expect_ok
    if otadata_mismatches:
        signals['otadata_expect_mismatches'] = ';'.join(otadata_mismatches)

    reg_snapshot = capture_boot_registers()
    if reg_snapshot is not None:
        signals['boot_register_snapshot'] = reg_snapshot

    # Max reset vector offset: check that the reset vector (word at offset 4
    # from VTOR) does not point beyond the authenticated image boundary.
    reset_vector_offset_ok = True
    if max_reset_vector_offset is not None and boot_slot is not None and boot_slot in slot_ranges:
        s_lo, s_hi = slot_ranges[boot_slot]
        try:
            reset_vector_addr = as_int(bus.ReadDoubleWord(actual_vtor + 4))
            signals['reset_vector_addr'] = fmt_u32(reset_vector_addr)
            # Reset vector offset relative to slot base.
            if reset_vector_addr >= s_lo:
                rv_offset = reset_vector_addr - s_lo
            else:
                # Reset vector points below the slot base -- flag as anomaly.
                rv_offset = 0
                signals['reset_vector_below_slot'] = True
                reset_vector_offset_ok = False
            signals['reset_vector_offset'] = rv_offset
            if rv_offset > max_reset_vector_offset:
                reset_vector_offset_ok = False
                signals['reset_vector_offset_exceeded'] = True
        except Exception:
            signals['reset_vector_read_error'] = True
            reset_vector_offset_ok = False
    signals['reset_vector_offset_ok'] = reset_vector_offset_ok

    criteria_ok = marker_ok and otadata_expect_ok and rollback_ok and reset_vector_offset_ok
    expectations_met = vtor_ok and vtor_aligned and pc_ok and criteria_ok
    signals['expectations_met'] = expectations_met

    # Distinguish wall_timeout with active bootloader (still retrying,
    # just slow) from wall_timeout with stuck execution (real failure).
    # A timeout where the bootloader was still making NVM progress is
    # not a boot failure — it's an insufficient wall-clock budget.
    p2_reason = ''
    p2_writes = 0
    if p2_status is not None:
        p2_reason = str(p2_status.get('reason', ''))
        p2_writes = int(p2_status.get('writes', 0))
    is_wall_timeout = p2_reason.startswith('wall_timeout')

    # Keep execution failures separate from expectation mismatches:
    # a boot into a real slot with the "wrong" image/slot is not "no_boot".
    if not vtor_in_known_slot:
        if is_wall_timeout and p2_writes > 0:
            # Bootloader was actively writing to flash when we killed it.
            # This is a timeout, not a brick — the bootloader may have
            # recovered given more time.
            boot_outcome = 'timeout'
        else:
            boot_outcome = 'no_boot'
    elif not vtor_aligned:
        boot_outcome = 'misaligned_vtor'
    elif not pc_ok:
        boot_outcome = 'wrong_pc'
    elif not vtor_ok or not criteria_ok:
        boot_outcome = 'wrong_image'
    else:
        boot_outcome = 'success'

    return boot_outcome, boot_slot, signals


def capture_metadata_delta_snapshot():
    """Read all metadata_delta field values from NVM. Returns dict of name->value."""
    if not metadata_delta_enabled:
        return None
    snapshot = {}
    for field in metadata_delta_fields:
        try:
            val = as_int(bus.ReadDoubleWord(field['address']))
            snapshot[field['name']] = val
        except Exception:
            snapshot[field['name']] = None
    return snapshot


def evaluate_metadata_delta(pre_snapshot, post_snapshot, marker_written):
    """Compare pre-fault and post-boot metadata field values.

    Returns (violations_list, delta_signals_dict).
    Each violation is a dict with field name, expected delta range, actual delta,
    and a finding_category string.

    Only supported by fault runners that perform real emulated boot cycles
    (run_execute_fault, run_trace_replay_fault and their native variants).
    Not supported by run_state_fault (no bootloader execution),
    instruction_skip, or hook_fault runners (which build results via
    _build_fault_result with metadata_delta_pre_snapshot=None).
    """
    if not metadata_delta_enabled or pre_snapshot is None or post_snapshot is None:
        return [], {}
    violations = []
    delta_signals = {}
    for field in metadata_delta_fields:
        name = field['name']
        pre_val = pre_snapshot.get(name)
        post_val = post_snapshot.get(name)
        if pre_val is None or post_val is None:
            continue
        delta = post_val - pre_val
        delta_signals[name + '_pre'] = fmt_u32(pre_val)
        delta_signals[name + '_post'] = fmt_u32(post_val)
        delta_signals[name + '_delta'] = delta

        # Check 'when' condition.
        when = field.get('when', 'always')
        if when == 'marker_written' and not marker_written:
            continue
        if when == 'marker_not_written' and marker_written:
            continue

        # Check delta bounds.
        min_d = field.get('min_delta')
        max_d = field.get('max_delta')
        violation = None
        if min_d is not None and delta < min_d:
            # Delta below minimum: boot count suppressed (never committed)
            # or rollback floor decreased.
            if 'boot_count' in name:
                category = 'boot_count_suppressed'
            elif 'rollback' in name or 'version' in name:
                category = 'rollback_floor_decreased'
            else:
                category = 'metadata_delta_below_min'
            violation = {
                'field': name,
                'address': fmt_u32(field['address']),
                'pre_value': fmt_u32(pre_val),
                'post_value': fmt_u32(post_val),
                'delta': delta,
                'min_delta': min_d,
                'max_delta': max_d,
                'when': when,
                'finding_category': category,
            }
        elif max_d is not None and delta > max_d:
            # Delta above maximum: boot count exhausted (trial burned
            # without firmware running).
            if 'boot_count' in name:
                category = 'boot_count_exhausted'
            else:
                category = 'metadata_delta_above_max'
            violation = {
                'field': name,
                'address': fmt_u32(field['address']),
                'pre_value': fmt_u32(pre_val),
                'post_value': fmt_u32(post_val),
                'delta': delta,
                'min_delta': min_d,
                'max_delta': max_d,
                'when': when,
                'finding_category': category,
            }
        if violation is not None:
            violations.append(violation)
    return violations, delta_signals


def _metadata_delta_marker_written(signals):
    """Determine if firmware actually wrote its success marker.

    The 'marker_ok' signal defaults to True when no content criterion is
    configured (no marker address, no image hash).  That default does NOT
    mean the marker was written -- it means content verification was not
    performed.  For metadata_delta 'when=marker_written' checks we need
    to know if the marker was *actually* written, not just whether content
    criteria were skipped.

    Returns True only when a content criterion was actively checked and
    passed: either the marker address value matched, or the image hash
    matched a known image.
    """
    if not isinstance(signals, dict):
        return False
    # If an image hash was computed, use that as the authoritative signal.
    hash_match = str(signals.get('image_hash_match', '') or '').strip().lower()
    if hash_match and hash_match not in ('', 'skipped', 'unknown'):
        return True
    if hash_match == 'unknown':
        return False
    # If a marker address was configured, check whether the actual marker
    # value is non-zero (the default/unconfigured state emits '0x00000000').
    marker_actual = signals.get('marker_actual')
    if marker_actual is not None:
        try:
            val = int(str(marker_actual), 0)
        except (ValueError, TypeError):
            val = 0
        if val != 0:
            # A non-zero marker_actual means the marker address was
            # configured and read.  marker_ok tells us if it matched.
            return bool(signals.get('marker_ok', False))
    # No content criterion was configured -- we cannot determine if the
    # marker was written.
    return False


def annotate_result_metadata_delta(result, pre_snapshot, marker_written=False):
    """Read post-boot metadata, evaluate deltas, and annotate the result dict."""
    if not metadata_delta_enabled or pre_snapshot is None:
        return
    post_snapshot = capture_metadata_delta_snapshot()
    if post_snapshot is None:
        return
    violations, delta_signals = evaluate_metadata_delta(
        pre_snapshot, post_snapshot, marker_written
    )
    if delta_signals:
        signals = result.get('signals')
        if isinstance(signals, dict):
            signals['metadata_delta'] = delta_signals
    if violations:
        result['metadata_delta_violations'] = violations


def run_state_fault(fault_at):
    # State mode: simulate staging->exec copy, fault at given index.
    # NOTE: metadata_delta is intentionally not supported in state mode.
    # State mode does not run the bootloader (no emulated boot cycles),
    # so there are no NVM metadata writes to track deltas on.
    fault_injected = False
    fault_address = 0
    actual_writes = 0

    for i in range(total_copy_writes):
        src = slot_staging_base + i * write_granularity
        dst = slot_exec_base + i * write_granularity

        if i == fault_at:
            if backend['kind'] == 'slow':
                backend['data'].InjectPartialWrite(dst)
            fault_injected = True
            fault_address = dst
            actual_writes = i
            break

        if write_granularity == 4:
            bus.WriteDoubleWord(dst, bus.ReadDoubleWord(src))
        else:
            bus.WriteQuadWord(dst, bus.ReadQuadWord(src))
        actual_writes = i + 1

    copy_completed = not fault_injected

    vector_base = int(slot_exec_base) + int(success_vector_offset)
    sp = as_int(bus.ReadDoubleWord(vector_base))
    reset_vector = as_int(bus.ReadDoubleWord(vector_base + 4))
    reset_pc = reset_vector & ~1

    vector_valid = (
        (sram_start <= sp <= sram_end)
        and ((reset_vector & 1) == 1)
        and (vector_base <= reset_pc < (slot_exec_base + slot_exec_size))
    )

    if copy_completed and vector_valid:
        boot_outcome = 'success'
    else:
        boot_outcome = 'hard_fault'

    boot_slot = None
    if vector_valid:
        for slot_name, (slot_lo, slot_hi) in slot_ranges.items():
            if slot_lo <= reset_pc < slot_hi:
                boot_slot = slot_name
                break

    if success_marker_addr != 0 and boot_outcome == 'success':
        actual_marker = as_int(bus.ReadDoubleWord(success_marker_addr))
        if actual_marker != success_marker_value:
            boot_outcome = 'hard_fault'
            boot_slot = None
    signals = {
        'vector_sp': fmt_u32(sp),
        'vector_reset': fmt_u32(reset_vector),
        'vector_valid': vector_valid,
        'vector_base': fmt_u32(vector_base),
        'copy_completed': copy_completed,
    }
    semantic_state = collect_semantic_state({
        'cycle': 0,
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'signals': signals,
        'fault_injected': bool(fault_injected),
        'stage': 'state_mode',
    })
    eff_criteria = get_effective_criteria('w')
    fault_class = classify_fault_result(boot_outcome, boot_slot, signals, effective_criteria=eff_criteria)

    result = {
        'fault_at': fault_at,
        'fault_requested': fault_at,
        'fault_type': 'w',
        'fault_injected': fault_injected,
        'fault_address': fmt_u32(fault_address),
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'fault_class': fault_class,
        'actual_writes': actual_writes,
        'signals': signals,
    }
    if eff_criteria is not None:
        result['effective_success_criteria'] = eff_criteria
    if semantic_state is not None:
        result['semantic_state'] = semantic_state
    return result

def run_until_done(cpu_ref, time_slice='0.02', max_iters=200, wall_timeout=120, label='',
                   expect_writes=True, stop_on_fault=True, op_trace=None, op_trace_limit=0,
                   zero_writes_is_brick=True, vtor_settle_iters=0):
    # Run CPU in continuous mode until it settles or budget exhausted.
    #
    # Uses `emulation RunFor` which runs in continuous mode — much faster
    # than cpu.Step() which uses single-step synchronization (~30x faster).
    #
    # vtor_settle_iters: after first VTOR capture, continue running for
    #   this many more iterations to let the boot complete and capture the
    #   final VTOR value. 0 = stop immediately on capture (default).
    #
    # Termination conditions (checked after each time slice):
    #   1. A fault that models immediate execution stop/power loss fired
    #   2. Write count unchanged for 3+ slices after writes started
    #   3. Zero writes after 5+ slices when expect_writes=False (bricked)
    #   4. No forward progress for progress_stall_timeout_s
    #   5. (no_boot profiles) no writes + no VTOR for N slices/min emulated time
    #   6. (no_boot profiles) writes settled (>0 but unchanged) + no VTOR
    #   7. Iteration limit or wall-clock timeout exhausted
    t0 = _time.time()
    prev_writes = -1
    zero_writes_count = 0
    no_boot_zero_write_count = 0
    no_boot_settled_count = 0
    prev_progress_key = None
    last_progress_t = t0
    last_progress_emulated_s = 0.0
    vtor_settle_remaining = -1
    try:
        slice_s = max(0.001, float(time_slice))
    except Exception:
        slice_s = 0.02
    emulated_s = 0.0
    reason = 'budget'
    iters = 0
    trace_limit_hit = False
    trace_prev_writes = 0
    trace_prev_erases = 0
    if op_trace is not None and op_trace_limit <= 0:
        op_trace_limit = 1024
    for iters in range(max_iters):
        monitor.Parse('emulation RunFor "{}"'.format(time_slice))
        emulated_s += slice_s
        if stop_on_fault and (fault_requires_immediate_stop() or was_otp_fault_injected()):
            reason = 'fault_fired'
            break
        # Early exit: check if VTOR has been set to a valid slot.
        # Bus watchpoints don't fire for SCB (CPU-private), so we poll.
        # Always poll — even after capture — so vtor_settle can update.
        vtor_now = as_int(bus.ReadDoubleWord(0xE000ED08))
        if vtor_now != 0:
            for sn, (s_lo, s_hi) in slot_ranges.items():
                if s_lo <= vtor_now < s_hi:
                    sticky_vtor['value'] = vtor_now
                    sticky_vtor['slot'] = sn
                    sticky_vtor['captured'] = True
                    break
        if sticky_vtor['captured']:
            if vtor_settle_remaining < 0:
                # First capture.
                if vtor_settle_iters == 0:
                    # Immediate stop (default/sweep behavior).
                    monitor.Parse('emulation RunFor "0.005"')
                    cfsr = as_int(bus.ReadDoubleWord(0xE000ED28))
                    if cfsr != 0:
                        # CFSR non-zero after VTOR capture. Only flag as hardfault if
                        # VTOR is NOT in the expected slot — post-handoff CFSR is the
                        # app's problem, not the bootloader's.
                        _vtor_expected = False
                        if success_vtor_slot == 'any':
                            _vtor_expected = sticky_vtor.get('slot') is not None
                        elif success_vtor_slot and success_vtor_slot in slot_ranges:
                            _vtor_expected = sticky_vtor.get('slot') == success_vtor_slot
                        reason = 'vtor_captured' if _vtor_expected else 'vtor_captured_hardfault'
                    else:
                        reason = 'vtor_captured'
                    break
                else:
                    # Start settle countdown.
                    vtor_settle_remaining = vtor_settle_iters
            elif vtor_settle_remaining > 0:
                vtor_settle_remaining -= 1
            else:
                # Settle countdown done — re-read VTOR to capture the
                # actual final value (may have changed during settle).
                vtor_final = as_int(bus.ReadDoubleWord(0xE000ED08))
                if vtor_final != 0:
                    for sn, (s_lo, s_hi) in slot_ranges.items():
                        if s_lo <= vtor_final < s_hi:
                            sticky_vtor['value'] = vtor_final
                            sticky_vtor['slot'] = sn
                            break
                monitor.Parse('emulation RunFor "0.005"')
                cfsr = as_int(bus.ReadDoubleWord(0xE000ED28))
                if cfsr != 0:
                    _vtor_expected = False
                    if success_vtor_slot == 'any':
                        _vtor_expected = sticky_vtor.get('slot') is not None
                    elif success_vtor_slot and success_vtor_slot in slot_ranges:
                        _vtor_expected = sticky_vtor.get('slot') == success_vtor_slot
                    reason = 'vtor_captured' if _vtor_expected else 'vtor_captured_hardfault'
                else:
                    reason = 'vtor_captured'
                break
        cur_writes = get_total_writes()
        cur_erases = get_total_erases()
        if op_trace is not None:
            pc_now = as_int(cpu_ref.GetRegisterUnsafe(15))
            if cur_writes < trace_prev_writes:
                trace_prev_writes = cur_writes
            while trace_prev_writes < cur_writes:
                trace_prev_writes += 1
                op_trace.append({
                    'seq': len(op_trace) + 1,
                    'op': 'write',
                    'index': trace_prev_writes,
                    'pc': fmt_u32(pc_now),
                    'emulated_s': round(emulated_s, 6),
                })
                if len(op_trace) >= op_trace_limit:
                    reason = 'op_trace_limit'
                    trace_limit_hit = True
                    break
            if trace_limit_hit:
                break
            if cur_erases < trace_prev_erases:
                trace_prev_erases = cur_erases
            while trace_prev_erases < cur_erases:
                trace_prev_erases += 1
                op_trace.append({
                    'seq': len(op_trace) + 1,
                    'op': 'erase',
                    'index': trace_prev_erases,
                    'pc': fmt_u32(pc_now),
                    'emulated_s': round(emulated_s, 6),
                })
                if len(op_trace) >= op_trace_limit:
                    reason = 'op_trace_limit'
                    trace_limit_hit = True
                    break
            if trace_limit_hit:
                break
        progress_key = (
            cur_writes,
            cur_erases,
            bool(sticky_vtor['captured']),
        )
        now = _time.time()
        if prev_progress_key is None or progress_key != prev_progress_key:
            prev_progress_key = progress_key
            last_progress_t = now
            last_progress_emulated_s = emulated_s
        elif progress_stall_timeout_s > 0:
            # Use EMULATED time for stall detection, not wall clock.
            # Wall-clock stall detection is non-deterministic: a slow CI
            # runner fires the stall timeout during CPU-intensive operations
            # (e.g. SHA-256 hash validation) while a fast runner does not,
            # producing different flash states and false-positive findings.
            emulated_stall = emulated_s - last_progress_emulated_s
            if emulated_stall >= progress_stall_timeout_s:
                if cur_writes == 0:
                    reason = 'no_boot_stall({:.2f}s_emulated)'.format(emulated_stall)
                else:
                    reason = 'no_progress_stall({:.2f}s_emulated)'.format(emulated_stall)
            break
        if cur_writes == 0 and not sticky_vtor['captured']:
            no_boot_zero_write_count += 1
        else:
            no_boot_zero_write_count = 0
        if (
            expect_control_outcome == 'no_boot'
            and no_boot_zero_write_count >= no_boot_zero_write_slices
            and emulated_s >= no_boot_min_emulated_s
        ):
            reason = 'no_boot_no_writes'
            break
        # No-boot with settled writes: bootloader wrote metadata (e.g. marking
        # a slot invalid) but then entered a recovery loop with no further
        # writes and no VTOR capture.  Detect by counting consecutive slices
        # where writes > 0 but unchanged and VTOR not captured.
        if (
            expect_control_outcome == 'no_boot'
            and cur_writes > 0
            and cur_writes == prev_writes
            and not sticky_vtor['captured']
        ):
            no_boot_settled_count += 1
        else:
            no_boot_settled_count = 0
        if (
            no_boot_settled_count >= no_boot_zero_write_slices
            and emulated_s >= no_boot_min_emulated_s
        ):
            reason = 'no_boot_settled_writes'
            break
        # Bricked device detection: no writes at all after several slices.
        # Some clean follow-up boots are legitimately read-only and should not
        # be cut off by this heuristic.
        if zero_writes_is_brick and cur_writes == 0 and not expect_writes:
            zero_writes_count += 1
            if zero_writes_count >= 5:
                reason = 'no_writes_brick'
                break
        else:
            zero_writes_count = 0
        prev_writes = cur_writes
        # Wall-clock timeout.
        elapsed = now - t0
        if elapsed > wall_timeout:
            reason = 'wall_timeout({:.0f}s)'.format(elapsed)
            break
    # If we hit max_iters while mid-settle, finalize the VTOR capture.
    if reason == 'budget' and vtor_settle_remaining >= 0 and sticky_vtor['captured']:
        vtor_final = as_int(bus.ReadDoubleWord(0xE000ED08))
        if vtor_final != 0:
            for sn, (s_lo, s_hi) in slot_ranges.items():
                if s_lo <= vtor_final < s_hi:
                    sticky_vtor['value'] = vtor_final
                    sticky_vtor['slot'] = sn
                    break
        monitor.Parse('emulation RunFor "0.005"')
        cfsr = as_int(bus.ReadDoubleWord(0xE000ED28))
        if cfsr != 0:
            _vtor_expected = False
            if success_vtor_slot == 'any':
                _vtor_expected = sticky_vtor.get('slot') is not None
            elif success_vtor_slot and success_vtor_slot in slot_ranges:
                _vtor_expected = sticky_vtor.get('slot') == success_vtor_slot
            reason = 'vtor_captured' if _vtor_expected else 'vtor_captured_hardfault'
        else:
            reason = 'vtor_captured'
    elapsed = _time.time() - t0
    writes_now = get_total_writes()
    erases_now = get_total_erases()
    pc_now = as_int(cpu_ref.GetRegisterUnsafe(15))
    log('run_done [{}]: reason={} iters={} writes={} pc={} elapsed={:.1f}s'.format(
        label, reason, iters + 1, writes_now,
        fmt_u32(pc_now), elapsed))
    return {
        'iters': iters + 1,
        'reason': reason,
        'elapsed_s': round(elapsed, 6),
        'emulated_s': round(emulated_s, 6),
        'writes': writes_now,
        'erases': erases_now,
        'pc': fmt_u32(pc_now),
        'op_trace_events': len(op_trace) if op_trace is not None else 0,
        'op_trace_truncated': bool(trace_limit_hit),
    }

def parse_duration_seconds(default=2.0):
    try:
        return max(0.02, float(run_duration))
    except Exception:
        return default

def phase1_max_iters(default_s=4.0, time_slice_s=0.02):
    duration_s = max(float(default_s), parse_duration_seconds(default=default_s))
    slice_s = max(0.001, float(time_slice_s))
    return max(200, int((duration_s / slice_s) + 0.999))

def run_read_bit_flip_fault(fault_at):
    # read_bit_flip: storage is correct, but a specific word returns
    # corrupted data on the FIRST read during boot.  Models transient
    # single-event upsets (SEU) on the NVM read bus.
    #
    # Only supported on native paths (NVMemory, MRAMMemory) where the
    # peripheral can intercept individual CPU reads.  Fast-path targets
    # (MappedMemory + NVMC) cannot intercept reads -- the CPU hits the
    # backing array directly -- so we skip with a clear diagnostic.
    eff_criteria = get_effective_criteria('f')
    cpu_ref = monitor.Machine['sysbus.cpu']
    fp_t0 = _time.time()
    log('fp={} type=f phase1_setup'.format(fault_at))

    # Use profile read_fault_config if available, else derive from fault_at.
    fault_word_offset = int(fault_at) * write_granularity
    base_seed = read_fault_seed if read_fault_seed else (0xBEEF ^ (int(fault_at) * 2654435761 & 0xFFFFFFFF))
    # Per-point seed: mix base seed with fault_at for uniqueness across points.
    fault_seed = (base_seed ^ (int(fault_at) * 2654435761)) & 0xFFFFFFFF
    fault_bit_flips = read_fault_bit_flips
    should_arm = _read_fault_should_arm(fault_seed, read_fault_probability)

    restore_phase1_baseline()
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False
    reset_nvmc_for_sweep()
    disarm_fault()
    reset_verification_probes()

    read_fault_address = 0
    original_word = 0
    corrupted_word = 0
    fault_injected = False
    read_fault_actually_fired = False
    skip_reason = None
    preflight = ensure_read_fault_preflight()

    # Compute target address: if read_fault_regions is configured, map
    # fault_at into the configured region space; otherwise use staging slot.
    if read_fault_regions:
        # Flatten regions into a total byte span, index into it.
        total_region_bytes = sum(e - s for s, e in read_fault_regions)
        byte_offset = (fault_word_offset) % total_region_bytes if total_region_bytes else 0
        accum = 0
        target_address = 0
        for rg_start, rg_end in read_fault_regions:
            rg_size = rg_end - rg_start
            if accum + rg_size > byte_offset:
                target_address = rg_start + (byte_offset - accum)
                # Align to write_granularity
                target_address = target_address & ~(write_granularity - 1)
                target_address = max(target_address, rg_start)
                break
            accum += rg_size
        else:
            target_address = read_fault_regions[0][0]
    else:
        target_address = slot_staging_base + fault_word_offset

    if not preflight.get('supported'):
        skip_reason = preflight.get('reason') or 'read_fault_backend_unsupported'
    elif not should_arm:
        skip_reason = 'probability_gate'
        log('fp={} type=f SKIP: probability gate did not arm fault (p={})'.format(
            fault_at, read_fault_probability))
    elif backend['kind'] == 'mram':
        read_fault_address = target_address
        nvm_offset = read_fault_address - nvm_base_address
        _rf_data = backend['data']
        if 0 <= nvm_offset < int(_rf_data.Size):
            original_word = as_int(bus.ReadDoubleWord(read_fault_address))
            _rf_data.ReadFaultEnabled = True
            _rf_data.ReadFaultAddress = nvm_offset
            _rf_data.ReadFaultSeed = fault_seed & 0xFFFFFFFF
            _rf_data.ReadFaultFired = False
            _rf_data.ReadFaultSkipCount = 0
            _rf_data.ReadFaultTotalReads = 0
            if hasattr(_rf_data, 'ReadFaultBitFlips'):
                _rf_data.ReadFaultBitFlips = fault_bit_flips if fault_bit_flips > 0 else 1
            corrupted_word = _compute_read_bit_flip(original_word, fault_seed, fault_bit_flips)
            log('fp={} type=f armed nvm_offset=0x{:X} orig=0x{:08X} expected_corrupt=0x{:08X}'.format(
                fault_at, nvm_offset, original_word, corrupted_word))
        else:
            skip_reason = 'address_out_of_range'
            log('fp={} type=f WARNING: fault address 0x{:X} outside NVM'.format(
                fault_at, read_fault_address))
    else:
        read_fault_address = target_address
        nvm_offset = read_fault_address - nvm_base_address
        nvm_ref = backend['data'].Nvm
        if 0 <= nvm_offset < int(nvm_ref.Size):
            original_word = as_int(bus.ReadDoubleWord(read_fault_address))
            nvm_ref.ReadFaultEnabled = True
            nvm_ref.ReadFaultAddress = nvm_offset
            nvm_ref.ReadFaultSeed = fault_seed & 0xFFFFFFFF
            nvm_ref.ReadFaultFired = False
            nvm_ref.ReadFaultSkipCount = 0
            nvm_ref.ReadFaultTotalReads = 0
            if hasattr(nvm_ref, 'ReadFaultBitFlips'):
                nvm_ref.ReadFaultBitFlips = fault_bit_flips if fault_bit_flips > 0 else 1
            corrupted_word = _compute_read_bit_flip(original_word, fault_seed, fault_bit_flips)
            log('fp={} type=f armed nvm_offset=0x{:X} orig=0x{:08X} expected_corrupt=0x{:08X}'.format(
                fault_at, nvm_offset, original_word, corrupted_word))
        else:
            skip_reason = 'address_out_of_range'
            log('fp={} type=f WARNING: fault address 0x{:X} outside NVM'.format(
                fault_at, read_fault_address))

    if skip_reason is not None:
        # Backend unsupported, probability gate, or address out of range --
        # return early with a clean unarmed result so the sweep can continue.
        phase1_ms = int((_time.time() - fp_t0) * 1000)
        signals_skip = {
            'read_fault_address': fmt_u32(0),
            'read_fault_original': fmt_u32(0),
            'read_fault_corrupted': fmt_u32(0),
            'read_fault_fired': False,
            'read_fault_skipped': True,
            'phase1_ms': phase1_ms,
            'phase2_ms': 0,
        }
        result = {
            'fault_at': fault_at,
            'fault_requested': fault_at,
            'fault_type': 'f',
            'fault_injected': False,
            'fault_address': fmt_u32(0),
            'boot_outcome': 'skipped',
            'boot_slot': None,
            'fault_class': 'skipped',
            'actual_writes': 0,
            'signals': signals_skip,
        }
        if skip_reason:
            result['skip_reason'] = skip_reason
        return result

    log('fp={} type=f phase2_step'.format(fault_at))
    arm_vtor_watchpoint()
    p2_status = run_until_done(
        cpu_ref,
        label='fp{}_f_p2'.format(fault_at),
        expect_writes=False,
        zero_writes_is_brick=False,
        wall_timeout=30,
        time_slice=phase2_time_slice,
    )
    disarm_vtor_watchpoint()

    phase1_ms = int((_time.time() - fp_t0) * 1000)

    # Disarm and check whether the fault actually fired (one-shot semantics).
    if backend['kind'] == 'mram':
        backend['data'].ReadFaultEnabled = False
        read_fault_actually_fired = bool(backend['data'].ReadFaultFired)
    else:
        nvm_ref = backend['data'].Nvm
        nvm_ref.ReadFaultEnabled = False
        read_fault_actually_fired = bool(nvm_ref.ReadFaultFired)
    fault_injected = read_fault_actually_fired

    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=fault_injected, effective_criteria=eff_criteria,
        p2_status=p2_status,
    )
    signals['read_fault_address'] = fmt_u32(read_fault_address)
    signals['read_fault_original'] = fmt_u32(original_word)
    signals['read_fault_corrupted'] = fmt_u32(corrupted_word)
    signals['read_fault_fired'] = read_fault_actually_fired
    signals['phase1_ms'] = phase1_ms
    signals['phase2_ms'] = 0
    signals['phase2_stop_reason'] = p2_status.get('reason')
    signals['phase2_emulated_s'] = p2_status.get('emulated_s')

    return _build_fault_result(
        fault_at, 'f', fault_injected, read_fault_address, 0, signals,
        boot_outcome=boot_outcome, boot_slot=boot_slot,
        eff_criteria=eff_criteria, p2_status=p2_status,
        followup_label='fp{}_readflip_followup'.format(fault_at),
    )


def _compute_read_bit_flip(value, seed, bit_flips=0):
    # Deterministic bit-flip using LCG PRNG (a*x+c mod 2^32).
    # If bit_flips > 0, use that exact count; otherwise derive from seed.
    seed = seed & 0xFFFFFFFF
    if seed == 0:
        seed = 0xDEAD
    flip_count = bit_flips if bit_flips > 0 else (1 + (seed % 3))
    flip_count = min(flip_count, 32)  # cannot flip more unique bits than exist
    used_bits = set()
    for i in range(flip_count):
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        bit_pos = seed % 32
        while bit_pos in used_bits:
            seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
            bit_pos = seed % 32
        used_bits.add(bit_pos)
        value ^= (1 << bit_pos)
    return value & 0xFFFFFFFF


def _read_fault_should_arm(seed, probability):
    if probability <= 0.0:
        return False
    if probability >= 1.0:
        return True
    seed = as_int(seed) & 0xFFFFFFFF
    if seed == 0:
        seed = 0x9E3779B9
    seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
    return (seed / 4294967296.0) < probability


def _read_fault_backend_support(obj, bit_flips):
    required = [
        'ReadFaultEnabled',
        'ReadFaultAddress',
        'ReadFaultSeed',
        'ReadFaultFired',
        'ReadFaultSkipCount',
        'ReadFaultTotalReads',
    ]
    missing = [name for name in required if not hasattr(obj, name)]
    if missing:
        return False, 'backend_missing_read_fault_properties: {}'.format(', '.join(missing))
    if bit_flips > 1 and not hasattr(obj, 'ReadFaultBitFlips'):
        return False, 'backend_missing_read_fault_bit_count_support'
    return True, ''


def ensure_read_fault_preflight():
    if read_fault_preflight.get('checked'):
        return read_fault_preflight
    read_fault_preflight['checked'] = True
    b = backend

    if b['kind'] == 'fast':
        read_fault_preflight['backend'] = 'fast'
        read_fault_preflight['supported'] = False
        read_fault_preflight['reason'] = 'fast_path_no_read_intercept'
        log('read_fault preflight: unsupported backend=fast reason={}'.format(
            read_fault_preflight['reason']))
        return read_fault_preflight

    backend_obj = b['data'] if b['kind'] == 'mram' else b['data'].Nvm
    read_fault_preflight['backend'] = b['kind']
    supported, reason = _read_fault_backend_support(backend_obj, read_fault_bit_flips)
    read_fault_preflight['supported'] = bool(supported)
    read_fault_preflight['reason'] = reason or ''
    if supported:
        log('read_fault preflight: supported backend={} bit_flips={}'.format(
            read_fault_preflight['backend'],
            read_fault_bit_flips if read_fault_bit_flips > 0 else 1,
        ))
    else:
        log('read_fault preflight: unsupported backend={} reason={}'.format(
            read_fault_preflight['backend'],
            read_fault_preflight['reason']))
    return read_fault_preflight


def ensure_command_fault_preflight():
    return {
        'supported': backend['supports_command_fault'],
        'reason': backend['command_fault_reason'],
    }


# ---------------------------------------------------------------------------
# Instruction skip (voltage glitch) fault injection.
# Models a voltage glitch that causes the CPU to skip one or more
# instructions by replacing them with Thumb NOP (0xBF00).
# ---------------------------------------------------------------------------
_instruction_skip_count = int(str(monitor.GetVariable('instruction_skip_count')).strip() or '1')


def invert_thumb_branch_halfword(halfword):
    halfword = int(halfword) & 0xFFFF
    # 16-bit B<cond> T1: 1101 cond imm8, cond 0..13 only.
    if (halfword & 0xF000) == 0xD000:
        cond = (halfword >> 8) & 0xF
        if cond < 0xE:
            return halfword ^ 0x0100
        return None
    # 16-bit CBZ/CBNZ T1.
    if (halfword & 0xF500) == 0xB100:
        return halfword ^ 0x0800
    return None


def patch_instruction_halfwords(skip_addr, skip_count, patch_model):
    original_halfwords = []
    patched_halfwords = []
    model = str(patch_model or 'nop').strip().lower() or 'nop'
    if model not in ('nop', 'branch_invert'):
        return {
            'supported': False,
            'reason': 'unknown_patch_model',
            'model': model,
            'original_halfwords': original_halfwords,
            'patched_halfwords': patched_halfwords,
        }
    if model == 'branch_invert' and int(skip_count) != 1:
        return {
            'supported': False,
            'reason': 'branch_invert_requires_single_halfword',
            'model': model,
            'original_halfwords': original_halfwords,
            'patched_halfwords': patched_halfwords,
        }
    for i in range(skip_count):
        addr = skip_addr + i * 2
        orig = int(bus.ReadWord(addr)) & 0xFFFF
        if model == 'nop':
            patched = 0xBF00
        else:
            patched = invert_thumb_branch_halfword(orig)
            if patched is None:
                return {
                    'supported': False,
                    'reason': 'branch_invert_not_supported_for_instruction',
                    'model': model,
                    'original_halfwords': original_halfwords + [orig],
                    'patched_halfwords': patched_halfwords,
                }
        original_halfwords.append(orig)
        patched_halfwords.append(int(patched) & 0xFFFF)
    for i, patched in enumerate(patched_halfwords):
        addr = skip_addr + i * 2
        bus.WriteWord(addr, patched)
    return {
        'supported': True,
        'reason': None,
        'model': model,
        'original_halfwords': original_halfwords,
        'patched_halfwords': patched_halfwords,
    }


def run_instruction_skip_fault(skip_addr, skip_count=None, patch_model='nop'):
    # Run a single instruction-skip fault: NOP the instruction(s) at
    # *skip_addr*, then boot the firmware and check recovery.
    #
    # The address is patched AFTER images and pre-boot state are loaded,
    # so the patch applies to the code the bootloader will execute.
    # After the test, images are reloaded to restore original code.
    if skip_count is None:
        skip_count = _instruction_skip_count
    skip_addr = int(skip_addr)
    eff_criteria = get_effective_criteria('i')
    fp_t0 = _time.time()
    log('fp=0x{:X} type=i skip_count={} phase1_setup'.format(skip_addr, skip_count))

    # Phase 1: restore baseline, apply the instruction skip patch, then boot.
    restore_phase1_baseline()
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False
    reset_nvmc_for_sweep()
    disarm_fault()

    patch_meta = patch_instruction_halfwords(skip_addr, skip_count, patch_model)
    original_halfwords = patch_meta.get('original_halfwords', [])
    patched_halfwords = patch_meta.get('patched_halfwords', [])
    if not patch_meta.get('supported'):
        return {
            'fault_at': skip_addr,
            'fault_requested': skip_addr,
            'fault_type': 'i:0x{:X}:{}'.format(skip_addr & 0xFFFFFFFF, patch_meta.get('model') or patch_model),
            'fault_injected': False,
            'fault_address': '0x{:08X}'.format(skip_addr & 0xFFFFFFFF),
            'boot_outcome': 'skipped',
            'boot_slot': None,
            'fault_class': 'skipped',
            'skip_reason': patch_meta.get('reason') or 'instruction_patch_unsupported',
            'signals': {
                'trace_replay_mode': 'execute',
                'skip_address': '0x{:08X}'.format(skip_addr & 0xFFFFFFFF),
                'skip_count': skip_count,
                'instruction_patch_model': patch_meta.get('model') or str(patch_model or 'nop'),
                'instruction_patch_supported': False,
                'instruction_patch_reason': patch_meta.get('reason') or 'instruction_patch_unsupported',
                'original_halfwords': ['0x{:04X}'.format(h) for h in original_halfwords],
            },
        }
    log('fp=0x{:X} type=i model={} patched {} halfword(s) at 0x{:08X}'.format(
        skip_addr, patch_meta.get('model'), skip_count, skip_addr & 0xFFFFFFFF))

    arm_vtor_watchpoint()
    p1_wall_timeout = max(120, progress_stall_timeout_s * 3)
    p1_max_iters = phase1_max_iters(default_s=4.0)
    phase1_status = run_until_done(
        cpu_ref,
        label='fp0x{:X}_p1'.format(skip_addr),
        stop_on_fault=False,
        max_iters=p1_max_iters,
        wall_timeout=p1_wall_timeout,
        vtor_settle_iters=_copy_on_boot_vtor_settle_iters(),
    )
    disarm_vtor_watchpoint()
    phase1_ms = int((_time.time() - fp_t0) * 1000)

    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=True, effective_criteria=eff_criteria
    )

    # Bus fault detection for instruction-skip: distinguish safe
    # denial-of-service (HardFault/BusFault on real silicon) from real
    # security bypasses.
    #
    # On Cortex-M3/M4/M7, CFSR bits [15:8] (BFSR) indicate BusFault
    # specifically.  On Cortex-M0/M0+ there is no CFSR — all faults
    # escalate to HardFault generically, so we can only check if PC
    # ended up in the HardFault handler.
    #
    # Note: Renode silently drops unmapped accesses (CFSR stays 0), so
    # the BFSR check only catches faults the emulator actually models.
    # The HardFault PC check catches cases where the bootloader has its
    # own fault handler that Renode vectored into.
    cfsr = as_int(bus.ReadDoubleWord(0xE000ED28))
    bfsr = (cfsr >> 8) & 0xFF  # BusFault Status Register is bits [15:8]
    ufsr = (cfsr >> 16) & 0xFFFF  # UsageFault Status Register
    signals['cfsr'] = fmt_u32(cfsr)
    signals['bfsr'] = '0x{:02X}'.format(bfsr)

    bus_fault_detected = False
    if bfsr != 0:
        # Definitive BusFault on M3+ — safe DoS on real silicon.
        bus_fault_detected = True
    elif ufsr != 0:
        # UsageFault (e.g. undefined instruction) — also safe DoS.
        bus_fault_detected = True

    # Check if PC landed in the HardFault handler.  Use the initial
    # vector table (address 0x0) since the bootloader may have changed
    # VTOR during execution.
    hardfault_entered = False
    try:
        initial_hardfault_handler = as_int(bus.ReadDoubleWord(0x0C))
        if initial_hardfault_handler != 0 and (pc_value & ~1) == (initial_hardfault_handler & ~1):
            hardfault_entered = True
    except Exception:
        pass
    # Also check phase1 stop reason.
    if phase1_status is not None and phase1_status.get('reason') == 'vtor_captured_hardfault':
        hardfault_entered = True

    signals['hardfault_entered'] = hardfault_entered
    signals['bus_fault_detected'] = bus_fault_detected

    # Only classify as bus_fault when we have specific evidence of a
    # memory/bus fault — not generic HardFault which could indicate
    # a real security-relevant crash worth investigating.
    if (bus_fault_detected or hardfault_entered) and boot_outcome != 'success':
        boot_outcome = 'bus_fault'

    signals['phase1_ms'] = phase1_ms
    signals['phase2_ms'] = 0
    signals['trace_replay_mode'] = 'execute'
    signals['skip_address'] = '0x{:08X}'.format(skip_addr & 0xFFFFFFFF)
    signals['skip_count'] = skip_count
    signals['instruction_patch_model'] = patch_meta.get('model') or str(patch_model or 'nop')
    signals['instruction_patch_supported'] = True
    signals['original_halfwords'] = ['0x{:04X}'.format(h) for h in original_halfwords]
    signals['patched_halfwords'] = ['0x{:04X}'.format(h) for h in patched_halfwords]
    merge_verification_probe_signals(signals)
    if phase1_status is not None:
        signals['phase1_stop_reason'] = phase1_status.get('reason')
        signals['phase1_emulated_s'] = phase1_status.get('emulated_s')

    return _build_fault_result(
        skip_addr, 'i', True,
        '0x{:08X}'.format(skip_addr & 0xFFFFFFFF),
        0, signals, boot_outcome=boot_outcome, boot_slot=boot_slot,
        eff_criteria=eff_criteria, p2_status=phase1_status,
        followup_label='fp0x{:X}_followup'.format(skip_addr),
    )


def run_timed_reset_fault(fault_at):
    # reset_at_time: run Phase 1 for a deterministic time offset, then
    # simulate a power reset regardless of write/erase boundaries.
    eff_criteria = get_effective_criteria('t')
    cpu_ref = monitor.Machine['sysbus.cpu']
    fp_t0 = _time.time()
    log('fp={} type=t phase1_setup'.format(fault_at))

    restore_phase1_baseline()
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False
    reset_nvmc_for_sweep()
    disarm_fault()

    duration_s = parse_duration_seconds(default=2.0)
    max_fp = max(fault_points) if fault_points else max(1, fault_at)
    frac = 0.0 if max_fp <= 0 else min(1.0, max(0.0, float(fault_at) / float(max_fp)))
    trigger_s = max(0.005, min(duration_s * 0.95, frac * duration_s))
    log('fp={} type=t trigger_s={:.3f} frac={:.3f}'.format(fault_at, trigger_s, frac))
    monitor.Parse('emulation RunFor "{:.3f}"'.format(trigger_s))

    fault_injected = True
    fault_address = 0
    actual_writes = get_total_writes() if backend['kind'] != 'slow' else 0

    if backend['kind'] == 'mram':
        mram_size = int(backend['data'].Size)
        saved_flash = backend['data'].ReadBytes(0, mram_size)
        fault_snapshot_bytes = to_py_bytes(saved_flash)
        restore_flash_and_boot(saved_flash)
        reset_nvmc_for_recovery()
    elif backend['kind'] == 'fast':
        flash_ref = backend['data'].Flash
        flash_size = int(backend['data'].FlashSize)
        saved_flash = flash_ref.ReadBytes(0, flash_size)
        fault_snapshot_bytes = to_py_bytes(saved_flash)
        restore_flash_and_boot(saved_flash)
        reset_nvmc_for_recovery()
    else:
        saved_flash = None
        fault_snapshot_bytes = None
        monitor.Parse('machine Reset')
        monitor.Parse('machine Pause')
        _bus_load_elf(bootloader_elf)
        restore_hw_init()

    log('fp={} type=t phase2_step'.format(fault_at))
    arm_vtor_watchpoint()
    p2_status = run_until_done(
        cpu_ref,
        label='fp{}_t_p2'.format(fault_at),
        expect_writes=False,
        zero_writes_is_brick=False,
        wall_timeout=30,
        time_slice=phase2_time_slice,
    )
    disarm_vtor_watchpoint()

    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=fault_injected, effective_criteria=eff_criteria,
        p2_status=p2_status,
    )
    signals['timed_reset_trigger_s'] = round(trigger_s, 6)
    signals['timed_reset_fraction'] = round(frac, 6)
    signals['timed_reset_elapsed_s'] = round(_time.time() - fp_t0, 6)
    signals['phase2_stop_reason'] = p2_status.get('reason')
    signals['phase2_emulated_s'] = p2_status.get('emulated_s')
    return _build_fault_result(
        fault_at, 't', fault_injected, fault_address, actual_writes, signals,
        boot_outcome=boot_outcome, boot_slot=boot_slot,
        eff_criteria=eff_criteria, p2_status=p2_status,
        followup_label='fp{}_timed_followup'.format(fault_at),
        saved_flash=saved_flash, fault_snapshot_bytes=fault_snapshot_bytes,
    )

def _generate_nvs_corruption(clean_data, mode, seed=0):
    # Generate a single corrupted NVS variant in-process.
    # Modes: bit_flip, partial_erase, truncate, scramble.
    # Returns corrupted bytes of same length as clean_data.
    import random as _rng_mod
    rng = _rng_mod.Random(seed)
    data = bytearray(clean_data)
    if mode == 'bit_flip':
        num_flips = max(1, min(8, len(data) // 256))
        for _ in range(num_flips):
            idx = rng.randint(0, len(data) - 1)
            bit = rng.randint(0, 7)
            data[idx] ^= (1 << bit)
    elif mode == 'partial_erase':
        half = len(data) // 2
        data[half:] = b'\xFF' * (len(data) - half)
    elif mode == 'truncate':
        if len(data) > 16:
            data[16:] = b'\x00' * (len(data) - 16)
    elif mode == 'scramble':
        for i in range(len(data)):
            data[i] = rng.randint(0, 255)
    return bytes(data)


def run_nvs_corruption_fault(variant_idx):
    # Run an NVS corruption fault: corrupt the NVS region, boot, check outcome.
    if nvs_region_addr is None or nvs_region_size is None or nvs_region_size == 0:
        return {
            'fault_at': variant_idx,
            'fault_requested': variant_idx,
            'fault_type': 'nv:{}'.format(variant_idx),
            'fault_injected': False,
            'fault_address': '0x00000000',
            'boot_outcome': 'skipped',
            'boot_slot': None,
            'fault_class': 'skipped',
            'actual_writes': 0,
            'signals': {'phase1_ms': 0, 'phase2_ms': 0, 'followup_ms': 0},
            'skip_reason': 'no_nvs_region_configured',
        }

    if variant_idx >= len(nvs_corruption_modes):
        return {
            'fault_at': variant_idx,
            'fault_requested': variant_idx,
            'fault_type': 'nv:{}'.format(variant_idx),
            'fault_injected': False,
            'fault_address': '0x00000000',
            'boot_outcome': 'skipped',
            'boot_slot': None,
            'fault_class': 'skipped',
            'actual_writes': 0,
            'signals': {'phase1_ms': 0, 'phase2_ms': 0, 'followup_ms': 0},
            'skip_reason': 'nvs_variant_index_out_of_range',
        }

    mode = nvs_corruption_modes[variant_idx]
    clean_data = _load_nvs_clean_data()
    corrupted = _generate_nvs_corruption(clean_data, mode, seed=nvs_corruption_seed + variant_idx)

    eff_criteria = get_effective_criteria('nv')
    cpu_ref = monitor.Machine['sysbus.cpu']
    fp_t0 = _time.time()
    log('nvs_corruption variant={} mode={} addr=0x{:08X} size={}'.format(
        variant_idx, mode, nvs_region_addr, nvs_region_size))

    # Reset machine and reload images.
    monitor.Parse('machine Reset')
    monitor.Parse('machine Pause')
    reload_images()
    apply_pre_boot_state()
    if _hash_bypass_active:
        apply_hash_bypass()

    # Write corrupted NVS data to the region.
    from System import Array, Byte
    arr = Array[Byte](len(corrupted))
    for i, b in enumerate(corrupted):
        arr[i] = b
    bus.WriteBytes(arr, nvs_region_addr)
    log('nvs_corruption: wrote {} bytes of mode={} to 0x{:08X}'.format(
        len(corrupted), mode, nvs_region_addr))

    prime_bootloader_entry()
    restore_hw_init()
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False
    reset_nvmc_for_sweep()
    disarm_fault()
    arm_vtor_watchpoint()
    p2_status = run_until_done(
        cpu_ref,
        label='nvs_{}'.format(variant_idx),
        expect_writes=False,
        zero_writes_is_brick=False,
        wall_timeout=30,
        time_slice=phase2_time_slice,
    )
    disarm_vtor_watchpoint()
    phase1_ms = int((_time.time() - fp_t0) * 1000)

    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=True, effective_criteria=eff_criteria,
        p2_status=p2_status,
    )
    signals['nvs_corruption_mode'] = mode
    signals['nvs_corruption_variant'] = variant_idx
    signals['phase1_ms'] = phase1_ms
    signals['phase2_ms'] = 0
    signals['phase2_stop_reason'] = p2_status.get('reason')
    signals['phase2_emulated_s'] = p2_status.get('emulated_s')
    return _build_fault_result(
        variant_idx, 'nv:{}'.format(variant_idx), True,
        '0x{:08X}'.format(nvs_region_addr),
        0, signals, boot_outcome=boot_outcome, boot_slot=boot_slot,
        eff_criteria=eff_criteria, p2_status=p2_status,
        followup_label='nvs_{}_followup'.format(variant_idx),
    )


def run_metadata_fault(fault_at, fault_type='w'):
    eff_criteria = get_effective_criteria('m')
    cpu_ref = monitor.Machine['sysbus.cpu']
    fp_t0 = _time.time()
    m_type = fault_type
    log('fp={} type=m:{} metadata_fault_setup'.format(fault_at, m_type))
    monitor.Parse('machine Reset')
    monitor.Parse('machine Pause')
    reload_images()
    if _hash_bypass_active:
        apply_hash_bypass()
    applied, fault_address, fault_injected = apply_partial_pre_boot_state(fault_at, fault_type=m_type)
    log('fp={} type=m:{} applied={} fault_addr=0x{:08X} injected={}'.format(fault_at, m_type, applied, fault_address, fault_injected))
    prime_bootloader_entry()
    restore_hw_init()
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False
    reset_nvmc_for_sweep()
    disarm_fault()
    arm_vtor_watchpoint()
    p2_status = run_until_done(cpu_ref, label='fp{}_m{}_boot'.format(fault_at, m_type), expect_writes=False, zero_writes_is_brick=False, wall_timeout=30, time_slice=phase2_time_slice)
    disarm_vtor_watchpoint()
    phase1_ms = int((_time.time() - fp_t0) * 1000)
    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(vtor_value, pc_value, fault_injected=fault_injected, effective_criteria=eff_criteria, p2_status=p2_status)
    signals['metadata_fault_applied'] = applied
    signals['metadata_fault_total'] = pre_boot_write_count
    signals['phase1_ms'] = phase1_ms
    signals['phase2_ms'] = 0
    signals['phase2_stop_reason'] = p2_status.get('reason')
    signals['phase2_emulated_s'] = p2_status.get('emulated_s')
    return _build_fault_result(
        fault_at, 'm:{}'.format(m_type), fault_injected, fault_address,
        applied, signals, boot_outcome=boot_outcome, boot_slot=boot_slot,
        eff_criteria=eff_criteria, p2_status=p2_status,
        followup_label='fp{}_meta_followup'.format(fault_at),
    )

def classify_fault_result(boot_outcome, boot_slot, signals, effective_criteria=None):
    if boot_outcome == 'success':
        return 'recoverable'
    if boot_outcome == 'wrong_image':
        eff_hash_slot = success_image_hash_slot
        eff_vtor = success_vtor_slot
        if effective_criteria is not None:
            eff_hash_slot = effective_criteria.get('image_hash_slot', success_image_hash_slot)
            eff_vtor = effective_criteria.get('vtor_slot', success_vtor_slot)
        hash_match = normalize_signal_token(signals.get('image_hash_match'))
        expected_slot = None
        if eff_hash_slot and eff_hash_slot != 'any':
            expected_slot = eff_hash_slot
        elif eff_vtor and eff_vtor in slot_ranges:
            expected_slot = eff_vtor
        if hash_match == 'unknown' and (expected_slot is None or expected_slot == boot_slot):
            return 'silent_corruption'
        return 'wrong_image'
    if boot_outcome == 'bus_fault':
        return 'safe_dos'
    if boot_outcome in ('wrong_pc', 'misaligned_vtor', 'hard_fault', 'no_boot'):
        return 'unrecoverable'
    return 'unrecoverable'


def _build_fault_result(fault_at, fault_type, fault_injected, fault_address,
                        actual_writes, signals, boot_outcome=None,
                        boot_slot=None, eff_criteria=None,
                        p2_status=None, followup_label='followup',
                        saved_flash=None, fault_snapshot_bytes=None,
                        extra_fields=None, metadata_delta_pre_snapshot=None):
    # Shared epilogue for all fault runners.
    #
    # Handles: classify_fault_result, run_followup_boot_cycles, semantic state
    # collection, postmortem dump, resume trace, and optional field attachment.
    # Returns the fully assembled result dict.
    #
    # Callers must have already called evaluate_boot_outcome() and populated
    # signals with timing/phase data BEFORE calling this.
    fault_class = classify_fault_result(
        boot_outcome, boot_slot, signals, effective_criteria=eff_criteria
    )
    # Metadata delta: capture post-recovery-boot snapshot BEFORE followup
    # boot cycles so the delta measures "pre-fault -> first recovery boot",
    # not "pre-fault -> after N followup boots".  Followup boots may
    # modify NVM metadata (e.g. incrementing boot counts), which would
    # pollute the delta if captured afterwards.
    _md_violations = None
    _md_delta_signals = None
    if metadata_delta_pre_snapshot is not None:
        _md_post_snapshot = capture_metadata_delta_snapshot()
        if _md_post_snapshot is not None:
            _md_marker_written = _metadata_delta_marker_written(signals)
            _md_violations, _md_delta_signals = evaluate_metadata_delta(
                metadata_delta_pre_snapshot, _md_post_snapshot, _md_marker_written
            )
    boot_cycle_records, multi_boot_analysis, followup_ms = run_followup_boot_cycles(
        boot_outcome,
        boot_slot,
        signals,
        initial_status=p2_status,
        fault_injected=fault_injected,
        label=followup_label,
        effective_criteria=eff_criteria,
    )
    signals['followup_ms'] = int(followup_ms)

    semantic_state = collect_semantic_state({
        'cycle': 0,
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'signals': signals,
        'fault_injected': bool(fault_injected),
        'stage': 'post_boot',
    })

    _fault_addr_int = None
    if isinstance(fault_address, int):
        _fault_addr_int = int(fault_address)
    elif isinstance(fault_address, str):
        try:
            _fault_addr_int = int(fault_address, 0)
        except Exception:
            _fault_addr_int = None
    if fault_snapshot_bytes is not None and _fault_addr_int is not None:
        try:
            _flash_base_addr, _flash_size = flash_geometry()
            _fault_off = _fault_addr_int - _flash_base_addr
            if 0 <= _fault_off <= len(fault_snapshot_bytes) - 4:
                _snapshot_word = struct.unpack_from('<I', fault_snapshot_bytes, _fault_off)[0]
                _final_word = as_int(bus.ReadDoubleWord(_fault_addr_int))
                signals['fault_snapshot_word'] = fmt_u32(_snapshot_word)
                signals['fault_final_word'] = fmt_u32(_final_word)
                signals['fault_word_changed_post_boot'] = bool(_final_word != _snapshot_word)
        except Exception:
            pass
    elif _fault_addr_int is not None and signals.get('fault_snapshot_word') is not None:
        try:
            _snapshot_word = int(str(signals.get('fault_snapshot_word')), 0)
            _final_word = as_int(bus.ReadDoubleWord(_fault_addr_int))
            signals['fault_final_word'] = fmt_u32(_final_word)
            signals['fault_word_changed_post_boot'] = bool(_final_word != _snapshot_word)
        except Exception:
            pass

    result = {
        'fault_at': fault_at,
        'fault_requested': fault_at,
        'fault_type': fault_type,
        'fault_injected': fault_injected,
        'fault_address': fmt_u32(fault_address) if isinstance(fault_address, int) else fault_address,
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'fault_class': fault_class,
        'actual_writes': actual_writes,
        'signals': signals,
    }
    if writeback_active():
        result['durability_model'] = 'writeback'
        result['writeback_capacity'] = writeback_capacity()

        # Per-fault-point writeback diagnostics: dirty domain state, write
        # counts, and commit ratio.  Uses trace data when available.
        _wb_diag_trace = trace_data_loaded
        if _wb_diag_trace is None and trace_file_path:
            try:
                _wb_diag_trace = load_trace_data(trace_file_path)
            except Exception:
                _wb_diag_trace = None
        _wb_diag_erase = erase_trace_loaded if erase_trace_loaded is not None else []
        if _wb_diag_trace:
            _wb_flash_base, _ = flash_geometry()
            _wb_ps = effective_page_size()
            _wb_dirty = writeback_dirty_state_at(
                _wb_diag_trace, _wb_diag_erase, fault_at,
                _wb_flash_base, _wb_ps,
            )
            _wb_total_issued = fault_at + 1 if fault_injected else actual_writes
            _wb_cap = writeback_capacity()
            _wb_total_pending = sum(d['pending'] for d in _wb_dirty.values())
            _wb_total_committed = max(0, _wb_total_issued - _wb_total_pending)
            _wb_commit_ratio = (
                round(float(_wb_total_committed) / _wb_total_issued, 4)
                if _wb_total_issued > 0 else 1.0
            )
            result['writeback_diagnostics'] = {
                'dirty_domains_at_fault': _wb_dirty,
                'writeback_stats': {
                    'writes_issued': _wb_total_issued,
                    'writes_committed': _wb_total_committed,
                    'write_differential': _wb_total_pending,
                    'commit_ratio': _wb_commit_ratio,
                },
            }
            # Tag fault_class when boot failed and overlay had pending data.
            if (
                fault_class in ('unrecoverable', 'wrong_image', 'silent_corruption')
                and _wb_total_pending > 0
                and fault_injected
            ):
                result['writeback_diagnostics']['writeback_buffer_loss'] = True
                if fault_class == 'unrecoverable':
                    result['fault_class'] = 'writeback_buffer_loss'
    elif durability_model != 'direct':
        result['durability_model'] = durability_model
    if eff_criteria is not None:
        result['effective_success_criteria'] = eff_criteria
    if semantic_state is not None:
        result['semantic_state'] = semantic_state
    if boot_cycle_records is not None:
        result['boot_cycles'] = boot_cycle_records
        result['multi_boot_analysis'] = multi_boot_analysis
    if boot_outcome == 'no_boot' and postmortem_dump_no_boot:
        dump_source = 'fault_snapshot' if fault_snapshot_bytes is not None else 'live_flash'
        result['postmortem_partition_dump'] = build_postmortem_partition_dump(
            snapshot_bytes=fault_snapshot_bytes,
            source=dump_source,
        )
    if (
        boot_outcome == 'no_boot'
        and resume_trace_no_boot
        and fault_injected
        and saved_flash is not None
    ):
        result['resume_trace'] = run_resume_trace_from_snapshot(
            saved_flash, fault_at, fault_type
        )
    # Apply deferred metadata delta results (captured before followup boots).
    if _md_delta_signals:
        signals['metadata_delta'] = _md_delta_signals
    if _md_violations:
        result['metadata_delta_violations'] = _md_violations

    if extra_fields:
        result.update(extra_fields)
    return result


def parse_write_trace_map(trace_text):
    flash_base, _ = flash_geometry()
    mapping = {}
    for line in trace_text.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        parts = line.split(':')
        if len(parts) < 2:
            continue
        write_idx = int(parts[0])
        flash_off = int(parts[1])
        value = int(parts[2]) if len(parts) >= 3 else 0
        mapping[write_idx] = {
            'flash_offset': flash_off,
            'address': fmt_u32(flash_base + flash_off),
            'value': fmt_u32(value),
        }
    return mapping

def parse_erase_trace_map(trace_text):
    flash_base, _ = flash_geometry()
    mapping = {}
    for line in trace_text.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        parts = line.split(':')
        if len(parts) < 2:
            continue
        erase_idx = int(parts[0])
        flash_off = int(parts[1])
        writes_at = int(parts[2]) if len(parts) >= 3 else 0
        erase_size = int(parts[3]) if len(parts) >= 4 else 0
        mapping[erase_idx] = {
            'flash_offset': flash_off,
            'address': fmt_u32(flash_base + flash_off),
            'writes_at_this_point': writes_at,
            'erase_size': erase_size,
        }
    return mapping

def run_resume_trace_from_snapshot(snapshot_flash, fault_at, fault_type):
    if backend['kind'] != 'fast':
        return {
            'enabled': False,
            'reason': 'fast_path_required',
        }
    if snapshot_flash is None:
        return {
            'enabled': False,
            'reason': 'missing_fault_snapshot',
        }

    cpu_ref = monitor.Machine['sysbus.cpu']
    restore_flash_and_boot(snapshot_flash)
    reset_nvmc_for_recovery()
    backend['data'].DiffLookahead = 2147483647
    backend['data'].WriteTraceClear()
    backend['data'].EraseTraceClear()
    backend['data'].WriteTraceEnabled = True
    backend['data'].EraseTraceEnabled = True

    op_events = []
    arm_vtor_watchpoint()
    status = run_until_done(
        cpu_ref,
        label='fp{}_resume_trace'.format(fault_at),
        expect_writes=False,
        zero_writes_is_brick=False,
        stop_on_fault=False,
        wall_timeout=resume_trace_wall_timeout_s,
        time_slice=resume_trace_time_slice,
        op_trace=op_events,
        op_trace_limit=resume_trace_max_ops,
    )
    disarm_vtor_watchpoint()

    backend['data'].WriteTraceEnabled = False
    backend['data'].EraseTraceEnabled = False
    write_map = parse_write_trace_map(backend['data'].WriteTraceToString())
    erase_map = parse_erase_trace_map(backend['data'].EraseTraceToString())

    enriched_ops = []
    for event in op_events:
        enriched = dict(event)
        if event.get('op') == 'write':
            meta = write_map.get(int(event.get('index', 0)))
            if meta:
                enriched.update(meta)
        elif event.get('op') == 'erase':
            meta = erase_map.get(int(event.get('index', 0)))
            if meta:
                enriched.update(meta)
        enriched_ops.append(enriched)

    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, _signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=True
    )

    return {
        'enabled': True,
        'fault_at': fault_at,
        'fault_type': fault_type,
        'stop_reason': status.get('reason'),
        'elapsed_s': status.get('elapsed_s'),
        'emulated_s': status.get('emulated_s'),
        'iters': status.get('iters'),
        'op_trace_truncated': status.get('op_trace_truncated', False),
        'final_pc': fmt_u32(pc_value),
        'final_vtor': fmt_u32(vtor_value),
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'total_writes': int(backend['data'].TotalWordWrites),
        'total_erases': int(backend['data'].TotalPageErases),
        'operation_count': len(enriched_ops),
        'nvm_operations': enriched_ops,
    }

def run_execute_fault(fault_at, fault_type='w'):
    # Execute mode: full CPU boot with fault injection.
    #
    # fault_type:
    #   write: 'w' power_loss, 'b' bit_corruption, 's' silent_write_failure,
    #          'g' driver_error, 'x' rc_injection, 'r' write_rejection,
    #          'd' write_disturb, 'l' wear_leveling_corruption
    #   erase: 'e' interrupted_erase, 'a' multi_sector_atomicity
    #   timed: 't' reset_at_time
    #   read:  'f' read_bit_flip (transient one-shot read corruption)
    #   ctrl:  'k' command_drop (drop one controller write command)
    #   i2c:   'in' i2c_nack, 'it' i2c_timeout, 'ib' i2c_bit_flip,
    #          'ic' i2c_truncated, 'iw' i2c_wrong_address
    #   cpu:   'i' instruction_skip (handled by run_instruction_skip_fault,
    #              dispatched from batch loop, NOT routed here)
    #
    # Fast path (NVMC CONFIG tracking): fault injection works by counting
    # NVMC CONFIG WEN->REN transitions. Power-loss-class faults stop phase 1
    # immediately. Corruption-class write faults mutate the targeted write but
    # let execution continue in the same boot attempt.
    #
    # Erase fault: counts ERASEPAGE operations. At the Nth erase, a
    # partial erase (first half only) simulates power loss mid-erase.
    #
    # Slow path (NVMemory): uses FaultAtWordWrite which corrupts the Nth
    # word during writing (partial-write fault injection).

    if fault_type == 't':
        return run_timed_reset_fault(fault_at)

    if fault_type == 'f':
        return run_read_bit_flip_fault(fault_at)

    if fault_type == 'k':
        preflight = ensure_command_fault_preflight()
        if not preflight.get('supported'):
            skip_reason = preflight.get('reason') or 'command_fault_backend_unsupported'
            return {
                'fault_at': fault_at,
                'fault_requested': fault_at,
                'fault_type': 'k',
                'fault_injected': False,
                'fault_address': fmt_u32(0),
                'boot_outcome': 'skipped',
                'boot_slot': None,
                'fault_class': 'skipped',
                'actual_writes': 0,
                'signals': {'phase1_ms': 0, 'phase2_ms': 0, 'followup_ms': 0},
                'skip_reason': skip_reason,
            }

    if fault_type in _I2C_WIRE_CODE_TO_FAULT_TYPE:
        preflight = ensure_i2c_fault_preflight()
        if not preflight.get('supported'):
            skip_reason = preflight.get('reason') or 'i2c_fault_backend_unsupported'
            return {
                'fault_at': fault_at,
                'fault_requested': fault_at,
                'fault_type': fault_type,
                'fault_injected': False,
                'fault_address': fmt_u32(0),
                'boot_outcome': 'skipped',
                'boot_slot': None,
                'fault_class': 'skipped',
                'actual_writes': 0,
                'signals': {'phase1_ms': 0, 'phase2_ms': 0, 'followup_ms': 0},
                'skip_reason': skip_reason,
            }

    if fault_type == 'x':
        preflight = ensure_rc_injection_preflight()
        if not preflight.get('supported'):
            raise RuntimeError(
                'rc_injection preflight failed: {}'.format(
                    preflight.get('reason') or 'symbol_resolution_failed'
                )
            )

    # Compute effective criteria for this fault type.
    # Control runs (fault_at < 0) always use global criteria.
    eff_criteria = get_effective_criteria(fault_type) if int(fault_at) >= 0 else None

    cpu_ref = monitor.Machine['sysbus.cpu']
    if int(fault_at) < 0:
        fp_t0 = _time.time()
        phase1_ms = 0
        phase1_status = None

        log('control phase1_setup')
        restore_phase1_baseline()
        reset_rc_injection_state(enabled=False)
        cpu_ref = monitor.Machine['sysbus.cpu']
        cpu_ref.IsHalted = False

        reset_nvmc_for_recovery()
        disarm_fault()

        arm_vtor_watchpoint()
        p1_wall_timeout = max(120, progress_stall_timeout_s * 3)
        p1_max_iters = phase1_max_iters(default_s=4.0)
        phase1_status = run_until_done(
            cpu_ref,
            label='control_p1',
            stop_on_fault=False,
            max_iters=p1_max_iters,
            wall_timeout=p1_wall_timeout,
            vtor_settle_iters=_copy_on_boot_vtor_settle_iters(),
        )
        disarm_vtor_watchpoint()
        phase1_ms = int((_time.time() - fp_t0) * 1000)

        actual_writes = get_total_writes()
        vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
        pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
        boot_outcome, boot_slot, signals = evaluate_boot_outcome(
            vtor_value, pc_value, fault_injected=False, effective_criteria=eff_criteria
        )
        signals['phase1_ms'] = phase1_ms
        signals['phase2_ms'] = 0
        signals['phase1_ops_total'] = actual_writes
        signals['trace_replay_mode'] = 'execute'
        if phase1_status is not None:
            signals['phase1_stop_reason'] = phase1_status.get('reason')
            signals['phase1_emulated_s'] = phase1_status.get('emulated_s')

        return _build_fault_result(
            fault_at, 'control', False, '0x00000000', actual_writes, signals,
            boot_outcome=boot_outcome, boot_slot=boot_slot,
            eff_criteria=eff_criteria, p2_status=phase1_status,
            followup_label='control_followup',
        )

    fp_t0 = _time.time()
    phase1_ms = 0
    phase2_ms = 0
    recovery_writes = None
    debug_trailer = None
    phase1_status = None
    phase2_status = None
    fault_snapshot_bytes = None
    saved_flash = None
    md_pre_snapshot = None
    is_erase_fault = fault_type in ('e', 'a')
    is_power_loss_fault = fault_type in ('w', 'e', 'a')
    is_non_power_write_fault = fault_type in ('b', 's', 'g', 'x', 'r', 'd', 'l', 'k')
    is_command_fault = fault_type == 'k'
    is_i2c_fault = fault_type in _I2C_WIRE_CODE_TO_FAULT_TYPE
    is_otp_fault = fault_type in _OTP_WIRE_CODES and backend.get('otp') is not None
    log('fp={} type={} phase1_setup'.format(fault_at, fault_type))

    # Phase 1: Reset and set up for the faulted boot.
    restore_phase1_baseline()

    # Capture metadata fields before fault injection for delta tracking.
    md_pre_snapshot = capture_metadata_delta_snapshot()
    reset_rc_injection_state(enabled=(fault_type == 'x'))
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False

    reset_nvmc_for_sweep()

    if is_erase_fault:
        # Erase faults: arm at the Nth erase operation.
        # 'e' = interrupted_erase (mode 0), 'a' = multi-sector atomicity (mode 1).
        erase_mode = 1 if fault_type == 'a' else 0
        base_erases = get_total_erases()
        arm_at = base_erases + fault_at + 1
        log('fp={} phase1_step erase_arm_at={} mode={}'.format(fault_at, arm_at, erase_mode))
        arm_erase_fault(arm_at, erase_fault_mode=erase_mode)
        disarm_write_fault()
    elif is_command_fault:
        base_commands = get_total_commands()
        arm_at = base_commands + fault_at + 1
        if arm_at > base_commands + max_writes_cap:
            arm_at = base_commands + max_writes_cap + 1
        log('fp={} phase1_step command_arm_at={} mode=1'.format(fault_at, arm_at))
        arm_controller_fault(arm_at, command_fault_mode=1)
        disarm_write_fault()
        disarm_erase_fault()
    elif is_i2c_fault:
        i2c_ft_code = _I2C_WIRE_CODE_TO_FAULT_TYPE[fault_type]
        base_txns = get_total_i2c_transactions()
        arm_at = base_txns + fault_at + 1
        if arm_at > base_txns + max_writes_cap:
            arm_at = base_txns + max_writes_cap + 1
        log('fp={} phase1_step i2c_arm_at={} type={}'.format(fault_at, arm_at, i2c_ft_code))
        arm_i2c_fault(arm_at, i2c_fault_type=i2c_ft_code)
        disarm_write_fault()
        disarm_erase_fault()
    elif is_otp_fault:
        blow_mode = _WRITE_FAULT_MODE.get(fault_type, 0)
        base_blows = get_total_otp_blows()
        arm_at = base_blows + fault_at + 1
        if arm_at > base_blows + max_writes_cap:
            arm_at = base_blows + max_writes_cap + 1
        log('fp={} phase1_step otp_arm_at={} mode={}'.format(fault_at, arm_at, blow_mode))
        arm_otp_fault(arm_at, blow_fault_mode=blow_mode)
        disarm_write_fault()
        disarm_erase_fault()
    else:
        # Write faults:
        #   'w' power_loss (0), 'b' bit_corruption (1),
        #   's' silent_write_failure (2), 'r' write_rejection (3),
        #   'd' write_disturb (4), 'l' wear_leveling_corruption (5),
        #   'g' driver_error (6), 'x' rc_injection (reuses mode 3).
        write_mode = _WRITE_FAULT_MODE.get(fault_type, 0)
        base_writes = get_total_writes()
        arm_at = base_writes + fault_at + 1
        if arm_at > base_writes + max_writes_cap:
            arm_at = base_writes + max_writes_cap + 1
        log('fp={} phase1_step write_arm_at={} mode={}'.format(fault_at, arm_at, write_mode))
        arm_fault(arm_at, write_fault_mode=write_mode)
        disarm_erase_fault()

    arm_vtor_watchpoint()
    p1_wall_timeout = max(120, progress_stall_timeout_s * 3)
    p1_max_iters = phase1_max_iters(default_s=4.0)
    phase1_status = run_until_done(
        cpu_ref,
        label='fp{}_p1'.format(fault_at),
        stop_on_fault=True,
        max_iters=p1_max_iters,
        wall_timeout=p1_wall_timeout,
        vtor_settle_iters=_copy_on_boot_vtor_settle_iters(),
    )
    disarm_vtor_watchpoint()
    phase1_ms = int((_time.time() - fp_t0) * 1000)
    phase1_stopped_on_fault = phase1_status is not None and phase1_status.get('reason') == 'fault_fired'

    if is_i2c_fault:
        fault_injected = was_i2c_fault_injected()
    elif is_otp_fault:
        fault_injected = was_otp_fault_injected()
    else:
        fault_injected = was_fault_injected()
    fault_address = get_last_command_address() if is_command_fault else get_last_write_address()
    if is_erase_fault:
        phase1_ops = get_total_erases()
    elif is_command_fault:
        phase1_ops = get_total_commands()
    elif is_i2c_fault:
        phase1_ops = get_total_i2c_transactions()
    elif is_otp_fault:
        phase1_ops = get_total_otp_blows()
    else:
        phase1_ops = get_total_writes()
    if fault_injected and phase1_stopped_on_fault:
        # Unified semantics: successful operations before the faulted operation.
        actual_writes = max(0, phase1_ops - 1)
    elif fault_injected and int(fault_at) >= 0:
        actual_writes = max(0, int(fault_at))
    else:
        actual_writes = phase1_ops
    log('fp={} type={} phase1_done injected={} ops_total={} ops_before_fault={}'.format(
        fault_at, fault_type, fault_injected, phase1_ops, actual_writes))
    disarm_fault()
    if is_otp_fault:
        disarm_otp_fault()

    if backend['kind'] != 'slow' and fault_injected:
        # Snapshot the faulted NVM state.
        if backend['kind'] == 'mram':
            mram_size = int(backend['data'].Size)
            saved_flash = backend['data'].ReadBytes(0, mram_size)
            fault_snapshot_bytes = to_py_bytes(saved_flash)
        else:
            flash_ref = backend['data'].Flash
            flash_size = int(backend['data'].FlashSize)
            saved_flash = backend['data'].FaultFlashSnapshot
            if saved_flash is None:
                log('fp={} WARNING: no snapshot, falling back to current flash'.format(fault_at))
                saved_flash = flash_ref.ReadBytes(0, flash_size)
            fault_snapshot_bytes = to_py_bytes(saved_flash)

        # Writeback durability: strip uncommitted writes from the snapshot.
        # In execute mode, the C# peripheral captured ALL writes in the
        # snapshot.  The writeback model says the last `capacity` writes
        # are in a volatile buffer and lost on power failure.  We revert
        # them using the calibration trace data.
        if writeback_active() and fault_snapshot_bytes is not None and is_power_loss_fault:
            _wb_trace = trace_data_loaded
            if _wb_trace is None and trace_file_path:
                _wb_trace = load_trace_data(trace_file_path)
            _wb_erase = erase_trace_loaded if erase_trace_loaded is not None else []
            if _wb_trace:
                _wb_flash_base, _ = flash_geometry()
                _wb_page_size = effective_page_size()
                fault_snapshot_bytes, _wb_discarded = writeback_strip_uncommitted_from_snapshot(
                    fault_snapshot_bytes, _wb_trace, _wb_erase, fault_at,
                    _wb_flash_base, _wb_page_size,
                )
                # Convert Python bytes back to .NET byte[] for restore_flash_and_boot.
                import System as _WbSys
                saved_flash = _WbSys.Array.CreateInstance(_WbSys.Byte, len(fault_snapshot_bytes))
                for _wbi in range(len(fault_snapshot_bytes)):
                    saved_flash[_wbi] = fault_snapshot_bytes[_wbi]
                log('fp={} writeback: stripped {} uncommitted writes from snapshot'.format(
                    fault_at, _wb_discarded))
            else:
                log('fp={} writeback: WARNING no trace data, using full snapshot (direct-mode fallback)'.format(fault_at))

        if phase1_stopped_on_fault and is_power_loss_fault:
            # Power-loss class: simulate a cold reset and recovery boot.
            if success_marker_addr != 0:
                flash_base_addr, _ = flash_geometry()
                def read_u32_from_snapshot(bus_addr):
                    offset = bus_addr - flash_base_addr
                    if 0 <= offset <= len(saved_flash) - 4:
                        return struct.unpack_from('<I', bytes(saved_flash), offset)[0]
                    return 0xDEAD
                pri_end = slot_exec_base + slot_exec_size
                sec_end = slot_staging_base + slot_staging_size
                pri_magic = [read_u32_from_snapshot(pri_end - 16 + i*4) for i in range(4)]
                pri_done  = read_u32_from_snapshot(pri_end - 32)
                pri_ok    = read_u32_from_snapshot(pri_end - 24)
                sec_magic = [read_u32_from_snapshot(sec_end - 16 + i*4) for i in range(4)]
                sec_done  = read_u32_from_snapshot(sec_end - 32)
                sec_ok    = read_u32_from_snapshot(sec_end - 24)
                debug_trailer = {
                    'pri_magic': [fmt_u32(m) for m in pri_magic],
                    'pri_copy_done': fmt_u32(pri_done),
                    'pri_image_ok': fmt_u32(pri_ok),
                    'sec_magic': [fmt_u32(m) for m in sec_magic],
                    'sec_copy_done': fmt_u32(sec_done),
                    'sec_image_ok': fmt_u32(sec_ok),
                }

            phase2_t0 = _time.time()
            restore_flash_and_boot(saved_flash)
            if _hash_bypass_active:
                apply_hash_bypass()
            reset_nvmc_for_recovery()

            log('fp={} phase2_step'.format(fault_at))
            arm_vtor_watchpoint()
            phase2_status = run_until_done(
                cpu_ref,
                label='fp{}_p2'.format(fault_at),
                expect_writes=False,
                zero_writes_is_brick=False,
                wall_timeout=30,
                stop_on_fault=False,
                time_slice=phase2_time_slice,
            )
            disarm_vtor_watchpoint()
            recovery_writes = get_total_writes()
            phase2_ms = int((_time.time() - phase2_t0) * 1000)
            log('fp={} phase2_done rec_writes={}'.format(fault_at, recovery_writes))
        elif phase1_stopped_on_fault and is_non_power_write_fault:
            # Legacy fallback: if a non-power-loss fault still halted phase 1,
            # restore the faulted state and continue the interrupted boot.
            phase2_t0 = _time.time()
            monitor.Parse('machine Pause')
            if backend['kind'] == 'mram':
                backend['data'].WriteBytes(0, saved_flash, 0, len(saved_flash))
                backend['data'].LastFaultInjected = False
            else:
                flash_ref.WriteBytes(0, saved_flash)
                backend['data'].FaultFired = False
                backend['data'].EraseFaultFired = False
            disarm_fault()
            cpu_ref.IsHalted = False
            log('fp={} phase1_continue_non_power'.format(fault_at))
            arm_vtor_watchpoint()
            phase2_status = run_until_done(
                cpu_ref,
                label='fp{}_p1c'.format(fault_at),
                wall_timeout=30,
                stop_on_fault=False,
                time_slice=phase2_time_slice,
            )
            disarm_vtor_watchpoint()
            phase2_ms = int((_time.time() - phase2_t0) * 1000)
    elif backend['kind'] == 'slow' and fault_injected and is_power_loss_fault and phase1_stopped_on_fault:
        # Slow path power-loss: NVMemory is non-volatile and retains the
        # faulted write across machine Reset.  Reset CPU, reload bootloader
        # ELF and slot images (MappedMemory regions are cleared by reset,
        # but NVMemory preserves faulted metadata), then run Phase 2.
        phase2_t0 = _time.time()
        monitor.Parse('machine Reset')
        monitor.Parse('machine Pause')
        _bus_load_elf(bootloader_elf)
        if image_exec_path:
            _bus_load_binary(image_exec_path, slot_exec_base)
        if image_staging_path:
            _bus_load_binary(image_staging_path, slot_staging_base)
        if _hash_bypass_active:
            apply_hash_bypass()
        reset_nvmc_for_recovery()

        log('fp={} phase2_step (slow path)'.format(fault_at))
        arm_vtor_watchpoint()
        phase2_status = run_until_done(
            cpu_ref,
            label='fp{}_p2'.format(fault_at),
            expect_writes=False,
            zero_writes_is_brick=False,
            wall_timeout=30,
            stop_on_fault=False,
            time_slice=phase2_time_slice,
        )
        disarm_vtor_watchpoint()
        recovery_writes = get_total_writes()
        phase2_ms = int((_time.time() - phase2_t0) * 1000)
        log('fp={} phase2_done rec_writes={}'.format(fault_at, recovery_writes))
    elif fault_injected and is_non_power_write_fault and phase1_stopped_on_fault:
        # Slow path non-power-loss: continue in the same boot attempt.
        phase2_t0 = _time.time()
        arm_vtor_watchpoint()
        phase2_status = run_until_done(
            cpu_ref,
            label='fp{}_p1c'.format(fault_at),
            wall_timeout=30,
            stop_on_fault=False,
            time_slice=phase2_time_slice,
        )
        disarm_vtor_watchpoint()
        phase2_ms = int((_time.time() - phase2_t0) * 1000)
    elif fault_injected and is_i2c_fault:
        # I2C bus fault: no flash corruption, boot continues in the same
        # attempt.  The I2CFaultProxy already injected the bus-level fault
        # (NACK/timeout/bit-flip/etc); just let the CPU keep running.
        phase2_t0 = _time.time()
        disarm_i2c_fault()
        arm_vtor_watchpoint()
        phase2_status = run_until_done(
            cpu_ref,
            label='fp{}_i2c_cont'.format(fault_at),
            wall_timeout=30,
            stop_on_fault=False,
            time_slice=phase2_time_slice,
        )
        disarm_vtor_watchpoint()
        phase2_ms = int((_time.time() - phase2_t0) * 1000)

    # Multi-boot for continue-after-fault: if the first boot completed
    # naturally but boot_cycles > 1, reboot to see if corrupted trailer
    # state causes wrong outcome on subsequent boots.
    _multiboot_cycles_run = 0
    if (fault_injected and is_non_power_write_fault
            and not phase1_stopped_on_fault and boot_cycles > 1):
        for extra_cycle in range(1, boot_cycles):
            _multiboot_cycles_run += 1
            log('fp={} multi-boot cycle {} of {}'.format(fault_at, extra_cycle + 1, boot_cycles))
            monitor.Parse('machine Pause')
            monitor.Parse('machine Reset')
            _bus_load_elf(bootloader_elf)
            # Do NOT reload slot images — use whatever is on flash after boot 1
            if _hash_bypass_active:
                apply_hash_bypass()
            reset_nvmc_for_recovery()
            arm_vtor_watchpoint()
            cycle_status = run_until_done(
                cpu_ref,
                label='fp{}_cycle{}'.format(fault_at, extra_cycle + 1),
                expect_writes=False,
                zero_writes_is_brick=False,
                wall_timeout=60,
                stop_on_fault=False,
                time_slice=phase2_time_slice,
            )
            disarm_vtor_watchpoint()
            log('fp={} cycle {} done'.format(fault_at, extra_cycle + 1))

    # Read final state.
    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=fault_injected, effective_criteria=eff_criteria
    )
    signals['phase1_ms'] = phase1_ms
    signals['phase2_ms'] = phase2_ms
    signals['phase1_ops_total'] = phase1_ops
    signals['trace_replay_mode'] = 'execute'
    signals['multiboot_cycles_run'] = _multiboot_cycles_run
    if phase1_status is not None:
        signals['phase1_stop_reason'] = phase1_status.get('reason')
        signals['phase1_emulated_s'] = phase1_status.get('emulated_s')
    if fault_injected and is_non_power_write_fault and not phase1_stopped_on_fault:
        signals['phase1_continued_after_fault'] = True
    if fault_injected and fault_type == 'g':
        signals['driver_error_flag_set'] = driver_error_flag_set()
        signals['driver_error_model'] = 'peripheral_status_flag'
    if fault_type == 'x':
        signals['rc_injection_model'] = 'software_return_code'
        signals['rc_injection_value'] = fmt_u32(_rc_injection_state['return_value'])
        signals['rc_injection_applied'] = bool(_rc_injection_state.get('injected'))
        if _rc_injection_state.get('injected_symbol'):
            signals['rc_injection_symbol'] = _rc_injection_state.get('injected_symbol')
        if _rc_injection_state.get('injected_return_addr') is not None:
            signals['rc_injection_return_addr'] = fmt_u32(_rc_injection_state.get('injected_return_addr'))
    if phase2_status is not None:
        signals['phase2_stop_reason'] = phase2_status.get('reason')
        signals['phase2_emulated_s'] = phase2_status.get('emulated_s')

    # Build extra fields specific to run_execute_fault.
    extras = {}
    if not fault_injected and int(fault_at) >= 0:
        extras['skip_reason'] = 'fault_index_beyond_total'
    if backend['kind'] != 'slow' and fault_injected and is_power_loss_fault:
        if debug_trailer is not None:
            extras['debug_trailer'] = debug_trailer
        extras['recovery_writes'] = recovery_writes

    result = _build_fault_result(
        fault_at, fault_type, fault_injected, fault_address,
        actual_writes, signals, boot_outcome=boot_outcome,
        boot_slot=boot_slot, eff_criteria=eff_criteria,
        p2_status=phase2_status,
        followup_label='fp{}_followup'.format(fault_at),
        saved_flash=saved_flash if is_power_loss_fault else None,
        fault_snapshot_bytes=fault_snapshot_bytes,
        extra_fields=extras,
        metadata_delta_pre_snapshot=md_pre_snapshot,
    )

    # Release large .NET byte[] to prevent memory exhaustion in batch mode.
    if backend['kind'] == 'fast':
        backend['data'].FaultFlashSnapshot = None

    return result

def run_cascading_fault(write_fault_at, erase_fault_at):
    # Cascading fault: write fault in Phase 1 creates dirty flash state,
    # erase fault in Phase 2 interrupts recovery.  Phase 3 checks if the
    # device survives two consecutive power losses.
    #
    # This catches bugs where:
    #   1. First power loss leaves partial swap state (scratch has data)
    #   2. Recovery boot erases scratch in a vulnerable order
    #   3. Second power loss mid-erase leaves stale trailer + corrupted data
    #   4. Third boot reads corrupted state → brick
    #
    # General class: any bootloader with "resume interrupted operation"
    # is potentially vulnerable to faults during the resume itself.

    cpu_ref = monitor.Machine['sysbus.cpu']
    fp_t0 = _time.time()
    log('cascade w={} e={} phase1_setup'.format(write_fault_at, erase_fault_at))

    # --- Phase 1: write fault to create dirty state ---
    monitor.Parse('machine Pause')
    cpu_ref.IsHalted = False
    monitor.Parse('machine Reset')
    reload_images_cached()
    apply_pre_boot_state()

    reset_nvmc_for_sweep()

    base_writes = get_total_writes()
    arm_at = base_writes + write_fault_at + 1
    if arm_at > base_writes + max_writes_cap:
        arm_at = base_writes + max_writes_cap + 1
    arm_fault(arm_at)
    disarm_erase_fault()

    run_until_done(cpu_ref, label='cascade_w{}_p1'.format(write_fault_at))
    disarm_fault()

    p1_injected = was_write_fault_injected()
    p1_writes = get_total_writes()
    p1_erases = get_total_erases()
    log('cascade w={} phase1_done injected={} writes={} erases={}'.format(
        write_fault_at, p1_injected, p1_writes, p1_erases))

    if not (backend['kind'] != 'slow' and p1_injected):
        # Phase 1 didn't fire — return as non-injected.
        return {
            'fault_at': write_fault_at,
            'fault_requested': write_fault_at,
            'fault_type': 'cascade',
            'fault_injected': False,
            'fault_address': '0x00000000',
            'boot_outcome': 'success',
            'boot_slot': None,
            'fault_class': 'recoverable',
            'actual_writes': p1_writes,
            'cascade': {
                'write_fault_at': write_fault_at,
                'erase_fault_at': erase_fault_at,
                'p1_injected': False,
            },
        }

    # --- Phase 2: recovery boot with erase fault armed ---
    flash_ref = backend['data'].Flash
    flash_size = int(backend['data'].FlashSize)
    saved_flash = backend['data'].FaultFlashSnapshot
    if saved_flash is None:
        saved_flash = flash_ref.ReadBytes(0, flash_size)

    restore_flash_and_boot(saved_flash)

    # Reset counters and arm erase fault for recovery boot.
    reset_nvmc_for_sweep()
    disarm_write_fault()
    arm_erase_fault(erase_fault_at + 1)  # 0-indexed → 1-indexed

    log('cascade w={} e={} phase2_step'.format(write_fault_at, erase_fault_at))
    run_until_done(
        cpu_ref,
        label='cascade_w{}_e{}_p2'.format(write_fault_at, erase_fault_at),
        time_slice=phase2_time_slice,
    )
    disarm_fault()

    p2_injected = was_erase_fault_injected()
    p2_erases = get_total_erases()
    p2_writes = get_total_writes()
    log('cascade w={} e={} phase2_done erase_injected={} erases={} writes={}'.format(
        write_fault_at, erase_fault_at, p2_injected, p2_erases, p2_writes))

    if not p2_injected:
        # Erase fault didn't fire during recovery (fewer erases than expected).
        # Read final state from Phase 2 directly.
        pass
    else:
        # --- Phase 3: boot from double-faulted state ---
        saved_flash2 = backend['data'].FaultFlashSnapshot
        if saved_flash2 is None:
            saved_flash2 = flash_ref.ReadBytes(0, flash_size)

        restore_flash_and_boot(saved_flash2)
        reset_nvmc_for_recovery()

        log('cascade w={} e={} phase3_step'.format(write_fault_at, erase_fault_at))
        arm_vtor_watchpoint()
        run_until_done(
            cpu_ref,
            label='cascade_w{}_e{}_p3'.format(write_fault_at, erase_fault_at),
            expect_writes=False,
            zero_writes_is_brick=False,
            wall_timeout=30,
            time_slice=phase2_time_slice,
        )
        disarm_vtor_watchpoint()

    # Read final state.
    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    eff_criteria = get_effective_criteria('w')
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=(p1_injected and p2_injected), effective_criteria=eff_criteria
    )
    fault_class = classify_fault_result(boot_outcome, boot_slot, signals, effective_criteria=eff_criteria)

    # Release large .NET byte[] to prevent memory exhaustion in batch mode.
    if backend['kind'] == 'fast':
        backend['data'].FaultFlashSnapshot = None

    elapsed = _time.time() - fp_t0
    result = {
        'fault_at': write_fault_at,
        'fault_requested': write_fault_at,
        'fault_type': 'cascade',
        'fault_injected': p1_injected and p2_injected,
        'fault_address': '0x00000000',
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'fault_class': fault_class,
        'actual_writes': p1_writes,
        'cascade': {
            'write_fault_at': write_fault_at,
            'erase_fault_at': erase_fault_at,
            'p1_injected': p1_injected,
            'p2_injected': p2_injected,
            'p2_erases': p2_erases,
            'p2_writes': p2_writes,
            'elapsed_s': round(elapsed, 1),
        },
        'signals': signals,
    }
    if eff_criteria is not None:
        result['effective_success_criteria'] = eff_criteria
    if boot_outcome == 'no_boot' and postmortem_dump_no_boot:
        snapshot = saved_flash2 if p2_injected else saved_flash
        result['postmortem_partition_dump'] = build_postmortem_partition_dump(
            snapshot_bytes=to_py_bytes(snapshot),
            source='fault_snapshot',
        )
    if boot_outcome == 'no_boot' and resume_trace_no_boot and p2_injected:
        result['resume_trace'] = run_resume_trace_from_snapshot(saved_flash2, write_fault_at, 'cascade')
    return result

# ---------------------------------------------------------------------------
# Phase 2 fault injection: generic 3-phase execution.
#
# Phase 1: inject fault at p1_fault_at to create degraded state
# Phase 2: recovery boot with fault injection armed at p2_fault_at
# Phase 3: boot from double-faulted state, validate recovery
# ---------------------------------------------------------------------------
def run_phase2_fault(p1_fault_at, p2_fault_at, p1_fault_type='w', p2_fault_type='w'):
    eff_criteria = get_effective_criteria('p2')
    cpu_ref = monitor.Machine['sysbus.cpu']
    fp_t0 = _time.time()
    is_p1_erase = p1_fault_type in ('e', 'a')
    is_p1_timed = p1_fault_type == 't'
    is_p2_erase = p2_fault_type in ('e', 'a')
    is_p2_timed = p2_fault_type == 't'
    p1_status = None
    p2_status = None
    log('p2fault p1={}/{} p2={}/{} phase1_setup'.format(
        p1_fault_at, p1_fault_type, p2_fault_at, p2_fault_type))

    # --- Phase 1: create degraded state ---
    restore_phase1_baseline()
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = False
    reset_nvmc_for_sweep()

    if is_p1_timed:
        # Timed reset Phase 1: run for a fractional duration then interrupt.
        disarm_fault()
        duration_s = parse_duration_seconds(default=2.0)
        max_fp = max(fault_points) if fault_points else max(1, p1_fault_at)
        frac = 0.0 if max_fp <= 0 else min(1.0, max(0.0, float(p1_fault_at) / float(max_fp)))
        trigger_s = max(0.005, min(duration_s * 0.95, frac * duration_s))
        log('p2fault p1={} type=t trigger_s={:.3f}'.format(p1_fault_at, trigger_s))
        monitor.Parse('emulation RunFor "{:.3f}"'.format(trigger_s))
        p1_injected = True  # Timed resets always "inject".
        p1_ops = get_total_writes() if backend['kind'] != 'slow' else 0
    elif is_p1_erase:
        erase_mode = 1 if p1_fault_type == 'a' else 0
        base_erases = get_total_erases()
        arm_at = base_erases + p1_fault_at + 1
        arm_erase_fault(arm_at, erase_fault_mode=erase_mode)
        disarm_write_fault()

        p1_wall_timeout = max(120, progress_stall_timeout_s * 3)
        p1_max_iters = phase1_max_iters(default_s=4.0)
        p1_status = run_until_done(
            cpu_ref,
            label='p2fault_p1_{}'.format(p1_fault_at),
            stop_on_fault=True,
            max_iters=p1_max_iters,
            wall_timeout=p1_wall_timeout,
        )
        disarm_fault()
        p1_injected = was_fault_injected()
        p1_ops = get_total_erases()
    else:
        write_mode = _WRITE_FAULT_MODE.get(p1_fault_type, 0)
        base_writes = get_total_writes()
        arm_at = base_writes + p1_fault_at + 1
        if arm_at > base_writes + max_writes_cap:
            arm_at = base_writes + max_writes_cap + 1
        arm_fault(arm_at, write_fault_mode=write_mode)
        disarm_erase_fault()

        p1_wall_timeout = max(120, progress_stall_timeout_s * 3)
        p1_max_iters = phase1_max_iters(default_s=4.0)
        p1_status = run_until_done(
            cpu_ref,
            label='p2fault_p1_{}'.format(p1_fault_at),
            stop_on_fault=True,
            max_iters=p1_max_iters,
            wall_timeout=p1_wall_timeout,
        )
        disarm_fault()
        p1_injected = was_fault_injected()
        p1_ops = get_total_writes()

    phase1_ms = int((_time.time() - fp_t0) * 1000)

    log('p2fault p1={}/{} phase1_done injected={} ops={}'.format(
        p1_fault_at, p1_fault_type, p1_injected, p1_ops))

    phase2_skip_reason = None
    if backend['kind'] == 'slow':
        phase2_skip_reason = 'unsupported_backend'
    elif not p1_injected:
        phase2_skip_reason = 'phase1_fault_not_injected'

    if phase2_skip_reason is not None:
        return {
            'fault_at': p1_fault_at,
            'fault_requested': p1_fault_at,
            'fault_type': 'p2',
            'fault_injected': False,
            'skip_reason': 'phase2_{}'.format(phase2_skip_reason),
            'fault_address': '0x00000000',
            'boot_outcome': 'skipped',
            'boot_slot': None,
            'fault_class': 'skipped',
            'actual_writes': p1_ops,
            'signals': {'phase1_ms': phase1_ms, 'phase2_ms': 0, 'phase3_ms': 0},
            'phase2_fault': {
                'p1_fault_at': p1_fault_at,
                'p2_fault_at': p2_fault_at,
                'p1_fault_type': p1_fault_type,
                'p2_fault_type': p2_fault_type,
                'p1_injected': False,
                'p2_injected': False,
                'skip_reason': phase2_skip_reason,
                'p2_total_ops': 0,
                'p2_max_fault_index': -1,
            },
        }

    # Snapshot faulted NVM from Phase 1.
    if backend['kind'] == 'mram':
        mram_size = int(backend['data'].Size)
        saved_flash_p1 = backend['data'].ReadBytes(0, mram_size)
    else:
        saved_flash_p1 = backend['data'].FaultFlashSnapshot
        if saved_flash_p1 is None:
            flash_ref = backend['data'].Flash
            flash_size = int(backend['data'].FlashSize)
            saved_flash_p1 = flash_ref.ReadBytes(0, flash_size)

    # --- Phase 2: recovery boot with fault armed ---
    phase2_t0 = _time.time()
    restore_flash_and_boot(saved_flash_p1)
    if _hash_bypass_active:
        apply_hash_bypass()

    reset_nvmc_for_sweep()

    if is_p2_timed:
        # Timed reset during recovery: run for a fractional duration of
        # the recovery boot, simulating a second power loss mid-recovery.
        disarm_fault()
        duration_s = parse_duration_seconds(default=2.0)
        p2_max_idx = max(fault_points) if fault_points else max(1, p2_fault_at)
        p2_frac = 0.0 if p2_max_idx <= 0 else min(1.0, max(0.0, float(p2_fault_at) / float(p2_max_idx)))
        p2_trigger_s = max(0.005, min(duration_s * 0.95, p2_frac * duration_s))
        log('p2fault p1={} p2={} type=t trigger_s={:.3f}'.format(
            p1_fault_at, p2_fault_at, p2_trigger_s))
        monitor.Parse('emulation RunFor "{:.3f}"'.format(p2_trigger_s))
        p2_injected = True  # Timed resets always "inject".
        p2_ops = get_total_writes() if backend['kind'] != 'slow' else 0
    elif is_p2_erase:
        erase_mode = 1 if p2_fault_type == 'a' else 0
        arm_erase_fault(p2_fault_at + 1, erase_fault_mode=erase_mode)
        disarm_write_fault()

        log('p2fault p1={} p2={}/{} phase2_step'.format(
            p1_fault_at, p2_fault_at, p2_fault_type))
        p2_status = run_until_done(
            cpu_ref,
            label='p2fault_p2_{}_{}'.format(p1_fault_at, p2_fault_at),
            stop_on_fault=True,
            time_slice=phase2_time_slice,
            wall_timeout=60,
        )
        disarm_fault()
        p2_injected = was_fault_injected()
        p2_ops = get_total_erases()
    else:
        write_mode = _WRITE_FAULT_MODE.get(p2_fault_type, 0)
        base_writes = get_total_writes()
        arm_at = base_writes + p2_fault_at + 1
        arm_fault(arm_at, write_fault_mode=write_mode)
        disarm_erase_fault()

        log('p2fault p1={} p2={}/{} phase2_step'.format(
            p1_fault_at, p2_fault_at, p2_fault_type))
        p2_status = run_until_done(
            cpu_ref,
            label='p2fault_p2_{}_{}'.format(p1_fault_at, p2_fault_at),
            stop_on_fault=True,
            time_slice=phase2_time_slice,
            wall_timeout=60,
        )
        disarm_fault()
        p2_injected = was_fault_injected()
        p2_ops = get_total_writes()

    phase2_ms = int((_time.time() - phase2_t0) * 1000)

    log('p2fault p1={} p2={}/{} phase2_done injected={} ops={}'.format(
        p1_fault_at, p2_fault_at, p2_fault_type, p2_injected, p2_ops))

    phase3_ms = 0
    p3_status = None
    if p2_injected:
        if backend['kind'] == 'mram':
            saved_flash_p2 = backend['data'].ReadBytes(0, mram_size)
        else:
            saved_flash_p2 = backend['data'].FaultFlashSnapshot
            if saved_flash_p2 is None:
                flash_ref = backend['data'].Flash
                flash_size = int(backend['data'].FlashSize)
                saved_flash_p2 = flash_ref.ReadBytes(0, flash_size)

        # --- Phase 3: boot from double-faulted state ---
        phase3_t0 = _time.time()
        restore_flash_and_boot(saved_flash_p2)
        if _hash_bypass_active:
            apply_hash_bypass()
        reset_nvmc_for_recovery()

        log('p2fault p1={} p2={} phase3_step'.format(p1_fault_at, p2_fault_at))
        arm_vtor_watchpoint()
        p3_status = run_until_done(
            cpu_ref,
            label='p2fault_p3_{}_{}'.format(p1_fault_at, p2_fault_at),
            expect_writes=False,
            zero_writes_is_brick=False,
            wall_timeout=30,
            stop_on_fault=False,
            time_slice=phase2_time_slice,
        )
        disarm_vtor_watchpoint()
        phase3_ms = int((_time.time() - phase3_t0) * 1000)
    else:
        if is_p2_erase:
            phase2_skip_reason = 'no_erase_at_index'
        else:
            phase2_skip_reason = 'no_write_at_index'

    # Read final state.
    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=(p1_injected and p2_injected), effective_criteria=eff_criteria
    )
    signals['phase1_ms'] = phase1_ms
    signals['phase2_ms'] = phase2_ms
    signals['phase3_ms'] = phase3_ms
    signals['trace_replay_mode'] = 'execute'
    if p1_status is not None:
        signals['phase1_stop_reason'] = p1_status.get('reason')
    if p2_status is not None:
        signals['phase2_stop_reason'] = p2_status.get('reason')
    if p3_status is not None:
        signals['phase3_stop_reason'] = p3_status.get('reason')

    semantic_state = collect_semantic_state({
        'cycle': 0,
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'signals': signals,
        'fault_injected': bool(p1_injected and p2_injected),
        'stage': 'post_boot',
    })
    fault_class = classify_fault_result(boot_outcome, boot_slot, signals, effective_criteria=eff_criteria)

    if backend['kind'] == 'fast':
        backend['data'].FaultFlashSnapshot = None

    elapsed = _time.time() - fp_t0
    result = {
        'fault_at': p1_fault_at,
        'fault_requested': p1_fault_at,
        'fault_type': 'p2',
        'fault_injected': p1_injected and p2_injected,
        'fault_address': '0x00000000',
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'fault_class': fault_class,
        'actual_writes': p1_ops,
        'signals': signals,
        'phase2_fault': {
            'p1_fault_at': p1_fault_at,
            'p2_fault_at': p2_fault_at,
            'p1_fault_type': p1_fault_type,
            'p2_fault_type': p2_fault_type,
            'p1_injected': p1_injected,
            'p2_injected': p2_injected,
            'p2_ops': p2_ops,
            'p2_total_ops': p2_ops,
            'p2_max_fault_index': (p2_ops - 1) if p2_ops > 0 else -1,
            'skip_reason': phase2_skip_reason,
            'elapsed_s': round(elapsed, 1),
        },
    }
    if eff_criteria is not None:
        result['effective_success_criteria'] = eff_criteria
    if phase2_skip_reason is not None:
        result['skip_reason'] = 'phase2_{}'.format(phase2_skip_reason)
    if semantic_state is not None:
        result['semantic_state'] = semantic_state
    if boot_outcome == 'no_boot' and postmortem_dump_no_boot:
        snapshot = saved_flash_p2 if p2_injected else saved_flash_p1
        result['postmortem_partition_dump'] = build_postmortem_partition_dump(
            snapshot_bytes=to_py_bytes(snapshot),
            source='fault_snapshot',
        )
    if boot_outcome == 'no_boot' and resume_trace_no_boot and p2_injected:
        result['resume_trace'] = run_resume_trace_from_snapshot(
            saved_flash_p2, p1_fault_at, 'p2')

    log('p2fault p1={} p2={} done outcome={} class={} elapsed={:.1f}s'.format(
        p1_fault_at, p2_fault_at, boot_outcome, fault_class, elapsed))
    return result


def run_multi_fault_sequence(fault_sequence):
    cpu_ref = monitor.Machine['sysbus.cpu']
    seq = [int(x) for x in fault_sequence]
    if len(seq) < 2:
        raise ValueError('multi-fault sequence needs >= 2 fault points')

    seq_t0 = _time.time()
    per_fault_states = []
    saved_flash = None
    sequence_injected = True

    for idx, fault_at in enumerate(seq):
        stage_t0 = _time.time()
        stage_label = 'mf{}_{}'.format(idx + 1, fault_at)
        if idx == 0:
            log('mf seq={} phase1_setup'.format(seq))
            restore_phase1_baseline()
            cpu_ref = monitor.Machine['sysbus.cpu']
            cpu_ref.IsHalted = False
        else:
            log('mf seq={} restore_stage{}'.format(seq, idx + 1))
            restore_flash_and_boot(saved_flash)
            if _hash_bypass_active:
                apply_hash_bypass()
        reset_nvmc_for_sweep()

        base_writes = get_total_writes()
        arm_at = base_writes + fault_at + 1
        if arm_at > base_writes + max_writes_cap:
            arm_at = base_writes + max_writes_cap + 1
        arm_fault(arm_at)
        disarm_erase_fault()

        status = run_until_done(
            cpu_ref,
            label=stage_label,
            stop_on_fault=True,
            wall_timeout=60 if idx > 0 else max(120, progress_stall_timeout_s * 3),
            time_slice=phase2_time_slice if idx > 0 else '0.02',
        )
        disarm_fault()
        injected = was_write_fault_injected()
        actual_writes = get_total_writes()
        stage_ms = int((_time.time() - stage_t0) * 1000)
        log('mf seq={} stage={} fault_at={} injected={} writes={}'.format(
            seq, idx + 1, fault_at, injected, actual_writes))

        stage_state = {
            'stage': idx + 1,
            'fault_at': fault_at,
            'fault_injected': bool(injected),
            'actual_writes': actual_writes,
            'signals': {
                'stage_ms': stage_ms,
                'stop_reason': status.get('reason') if status is not None else None,
                'emulated_s': status.get('emulated_s') if status is not None else None,
            },
        }

        if not injected:
            sequence_injected = False
            per_fault_states.append(stage_state)
            break

        if backend['kind'] == 'mram':
            mram_size = int(backend['data'].Size)
            saved_flash = backend['data'].ReadBytes(0, mram_size)
        else:
            saved_flash = backend['data'].FaultFlashSnapshot
            if saved_flash is None:
                flash_ref = backend['data'].Flash
                flash_size = int(backend['data'].FlashSize)
                saved_flash = flash_ref.ReadBytes(0, flash_size)

        per_fault_states.append(stage_state)

    if not sequence_injected:
        failed_stage = len(per_fault_states)
        max_writes = per_fault_states[-1].get('actual_writes', 0) if per_fault_states else 0
        return {
            'fault_at': seq[0],
            'fault_requested': seq[0],
            'fault_type': 'mf',
            'fault_sequence': seq,
            'fault_injected': False,
            'skip_reason': 'stage{}_fault_index_beyond_writes'.format(failed_stage),
            'fault_address': '0x00000000',
            'boot_outcome': 'skipped',
            'boot_slot': None,
            'fault_class': 'skipped',
            'actual_writes': max_writes,
            'per_fault_states': per_fault_states,
            'signals': {
                'multi_fault_count': len(seq),
                'failed_stage': failed_stage,
                'stage_max_writes': max_writes,
                'trace_replay_mode': 'execute',
                'sequence_elapsed_s': round(_time.time() - seq_t0, 1),
            },
        }

    recovery_t0 = _time.time()
    restore_flash_and_boot(saved_flash)
    if _hash_bypass_active:
        apply_hash_bypass()
    reset_nvmc_for_recovery()

    log('mf seq={} final_recovery_step'.format(seq))
    arm_vtor_watchpoint()
    final_status = run_until_done(
        cpu_ref,
        label='mf_final_{}'.format(seq[0]),
        expect_writes=False,
        zero_writes_is_brick=False,
        wall_timeout=30,
        stop_on_fault=False,
        time_slice=phase2_time_slice,
    )
    disarm_vtor_watchpoint()
    recovery_ms = int((_time.time() - recovery_t0) * 1000)

    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    eff_criteria = get_effective_criteria('w')
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=True, effective_criteria=eff_criteria
    )
    signals['multi_fault_count'] = len(seq)
    signals['multi_fault_recovery_ms'] = recovery_ms
    signals['trace_replay_mode'] = 'execute'
    if final_status is not None:
        signals['phase2_stop_reason'] = final_status.get('reason')
        signals['phase2_emulated_s'] = final_status.get('emulated_s')

    semantic_state = collect_semantic_state({
        'cycle': 0,
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'signals': signals,
        'fault_injected': True,
        'stage': 'post_boot',
    })
    fault_class = classify_fault_result(boot_outcome, boot_slot, signals, effective_criteria=eff_criteria)
    boot_cycle_records, multi_boot_analysis, followup_ms = run_followup_boot_cycles(
        boot_outcome,
        boot_slot,
        signals,
        initial_status=final_status,
        fault_injected=True,
        label='mf{}_followup'.format(seq[0]),
        effective_criteria=eff_criteria,
    )
    signals['followup_ms'] = int(followup_ms)

    result = {
        'fault_at': seq[0],
        'fault_requested': seq[0],
        'fault_type': 'mf',
        'fault_sequence': seq,
        'fault_injected': True,
        'fault_address': '0x00000000',
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'fault_class': fault_class,
        'actual_writes': per_fault_states[-1].get('actual_writes', 0) if per_fault_states else 0,
        'per_fault_states': per_fault_states,
        'signals': signals,
    }
    if eff_criteria is not None:
        result['effective_success_criteria'] = eff_criteria
    if semantic_state is not None:
        result['semantic_state'] = semantic_state
    if boot_cycle_records is not None:
        result['boot_cycles'] = boot_cycle_records
        result['multi_boot_analysis'] = multi_boot_analysis

    if backend['kind'] == 'fast':
        backend['data'].FaultFlashSnapshot = None

    return result

# ---------------------------------------------------------------------------
# Trace replay mode: reconstruct flash state from calibration trace instead
# of re-emulating Phase 1.  Eliminates the O(N^2) prefix cost — each fault
# point costs only O(K) Python writes + ~1s Phase 2 recovery boot.
# ---------------------------------------------------------------------------
trace_file_path = str(monitor.GetVariable('trace_file')).strip()
erase_trace_file_path = str(monitor.GetVariable('erase_trace_file')).strip()
trace_file_bin_path = str(monitor.GetVariable('trace_file_bin')).strip()
erase_trace_file_bin_path = str(monitor.GetVariable('erase_trace_file_bin')).strip()
trace_data_loaded = None
erase_trace_loaded = None
trace_replay_engine = None
trace_replay_engine_attempted = False

def ensure_trace_replay_engine():
    global trace_replay_engine, trace_replay_engine_attempted
    if trace_replay_engine is not None:
        return trace_replay_engine
    if trace_replay_engine_attempted:
        return None
    trace_replay_engine_attempted = True
    if backend['kind'] != 'fast':
        return None
    try:
        trace_replay_engine = monitor.Machine['sysbus.trace_replay']
        if trace_replay_engine.Target is None:
            trace_replay_engine.Target = backend['data'].Flash
            trace_replay_engine.TargetBaseAddress = int(backend['data'].FlashBaseAddress)
        log('trace_replay: native engine enabled')
        return trace_replay_engine
    except Exception as exc:
        log('trace_replay: native engine unavailable ({}); using python fallback'.format(exc))
        return None

def load_trace_data(path):
    import csv as _csv
    entries = []
    with open(path, 'r') as f:
        reader = _csv.DictReader(f)
        for row in reader:
            entries.append((
                int(row['write_index']),
                int(row['flash_offset']),
                int(row['value']),
            ))
    return entries

def load_erase_trace_data(path):
    import csv as _csv
    entries = []
    with open(path, 'r') as f:
        reader = _csv.DictReader(f)
        for row in reader:
            entries.append((
                int(row['flash_offset']),
                int(row.get('writes_at_this_point', 0)),
                int(row.get('erase_size', 0)),
            ))
    return entries


def decode_multi_fault_sequence_local(encoded):
    if not encoded.startswith('mf:'):
        raise ValueError('not a multi-fault encoding: {!r}'.format(encoded))
    parts = encoded.split(':')
    if len(parts) < 3:
        raise ValueError(
            'multi-fault encoding needs >= 2 fault points: {!r}'.format(encoded)
        )
    return [int(p) for p in parts[1:]]

_TRACE_REPLAY_WRITE_FAULT_TYPES = frozenset(('b', 's', 'r', 'd', 'l'))
_TRACE_REPLAY_SUPPORTED_FAULT_TYPES = frozenset(('w', 'b', 's', 'r', 'd', 'l'))


def to_clr_bytes(raw):
    import System
    if raw is None:
        return None
    arr = System.Array.CreateInstance(System.Byte, len(raw))
    for idx, value in enumerate(raw):
        arr[idx] = int(value) & 0xFF
    return arr


def _trace_replay_read_u32(image, offset):
    return struct.unpack_from('<I', image, int(offset))[0]


def _trace_replay_write_u32(image, offset, value):
    struct.pack_into('<I', image, int(offset), int(value) & 0xFFFFFFFF)


def _trace_replay_erase_region(image, offset, size, erase_fill):
    size = max(0, int(size))
    if size == 0:
        return
    start = int(offset)
    image[start:start + size] = bytes([int(erase_fill) & 0xFF]) * size


def _trace_replay_keep_one_to_zero_transitions(old_word, new_word, keep_mask):
    bits_to_flip = old_word & ~new_word
    actually_flipped = bits_to_flip & keep_mask
    return old_word & ~actually_flipped


def _trace_replay_next_lcg(seed):
    return (int(seed) * 1103515245 + 12345) & 0xFFFFFFFF


def _trace_replay_build_seed(offset, write_index, total_page_erases, corruption_seed=0):
    seed = int(corruption_seed) & 0xFFFFFFFF
    if seed == 0:
        seed = int(write_index) & 0xFFFFFFFF
    seed ^= int(offset) & 0xFFFFFFFF
    seed ^= (int(total_page_erases) * 2654435761) & 0xFFFFFFFF
    return seed & 0xFFFFFFFF


def _trace_replay_apply_write_fault(image, flash_off, value, fault_type, write_index,
                                    total_page_erases, page_size, corruption_seed=0):
    flash_off = int(flash_off)
    page_size = max(4, int(page_size))
    old_word = _trace_replay_read_u32(image, flash_off)
    new_word = int(value) & 0xFFFFFFFF

    if fault_type == 'b':
        seed = _trace_replay_build_seed(flash_off, write_index, total_page_erases, corruption_seed)
        keep_mask = _trace_replay_next_lcg(seed)
        corrupted = _trace_replay_keep_one_to_zero_transitions(old_word, new_word, keep_mask)
        _trace_replay_write_u32(image, flash_off, corrupted)
        return corrupted

    if fault_type == 's':
        silent_value = 0xFFFFFFFF if (int(write_index) & 1) == 0 else 0x00000000
        _trace_replay_write_u32(image, flash_off, silent_value)
        return silent_value

    if fault_type == 'r':
        _trace_replay_write_u32(image, flash_off, old_word)
        return old_word

    if fault_type == 'd':
        _trace_replay_write_u32(image, flash_off, new_word)
        seed = _trace_replay_build_seed(flash_off, write_index, total_page_erases, corruption_seed)
        for neighbor_off in (flash_off - 4, flash_off + 4):
            if neighbor_off < 0 or neighbor_off > len(image) - 4:
                continue
            neighbor_word = _trace_replay_read_u32(image, neighbor_off)
            seed = _trace_replay_next_lcg(seed)
            disturb_mask = seed & 0x11111111
            disturbed = neighbor_word & (~disturb_mask & 0xFFFFFFFF)
            _trace_replay_write_u32(image, neighbor_off, disturbed)
        return new_word

    if fault_type == 'l':
        _trace_replay_write_u32(image, flash_off, new_word)
        page_start = (flash_off // page_size) * page_size
        words_per_page = max(1, page_size // 4)
        error_count = 2 + min(10, int(total_page_erases) // 8)
        seed = _trace_replay_build_seed(flash_off, write_index, total_page_erases, corruption_seed)
        for _ in range(error_count):
            seed = _trace_replay_next_lcg(seed)
            idx = seed % words_per_page
            target_off = page_start + idx * 4
            if target_off < 0 or target_off > len(image) - 4:
                continue
            word = _trace_replay_read_u32(image, target_off)
            seed = _trace_replay_next_lcg(seed)
            mask = seed & 0x01010101
            if mask == 0:
                seed = _trace_replay_next_lcg(seed)
                mask = 1 << (seed % 32)
            aged = word & (~mask & 0xFFFFFFFF)
            _trace_replay_write_u32(image, target_off, aged)
        return new_word

    raise RuntimeError('trace replay write fault type {} unsupported'.format(fault_type))


def _build_trace_replay_write_fault_snapshot(fault_at, fault_type, flash_base_addr, flash_size,
                                             page_size, erase_fill):
    flash_ref = backend['data'].Flash
    flash_bytes = bytearray(to_py_bytes(flash_ref.ReadBytes(0, int(flash_size))))
    pending_erases = [(wap, foff, esz if esz > 0 else page_size) for foff, wap, esz in erase_trace_loaded]
    pending_erases.sort()
    erase_idx = 0
    total_page_erases = 0
    writes_applied = 0
    fault_injected = False
    fault_address = 0
    fault_snapshot_word = None
    target_write_index = int(fault_at) + 1
    corruption_seed = 0
    try:
        corruption_seed = int(getattr(backend['data'], 'CorruptionSeed', 0))
    except Exception:
        corruption_seed = 0

    for write_idx, flash_off, value in trace_data_loaded:
        while erase_idx < len(pending_erases) and pending_erases[erase_idx][0] < write_idx:
            _e_wap, e_off, e_sz = pending_erases[erase_idx]
            _trace_replay_erase_region(flash_bytes, e_off, e_sz, erase_fill)
            erase_idx += 1
            total_page_erases += 1

        if write_idx < target_write_index:
            _trace_replay_write_u32(flash_bytes, flash_off, value)
            writes_applied += 1
            continue

        if write_idx == target_write_index:
            fault_injected = True
            fault_address = int(flash_off) + int(flash_base_addr)
            fault_snapshot_word = _trace_replay_apply_write_fault(
                flash_bytes,
                flash_off,
                value,
                fault_type,
                write_idx,
                total_page_erases,
                page_size,
                corruption_seed=corruption_seed,
            )
            writes_applied += 1
            continue

        _trace_replay_write_u32(flash_bytes, flash_off, value)
        writes_applied += 1

    while erase_idx < len(pending_erases):
        _e_wap, e_off, e_sz = pending_erases[erase_idx]
        _trace_replay_erase_region(flash_bytes, e_off, e_sz, erase_fill)
        erase_idx += 1

    return to_clr_bytes(flash_bytes), fault_injected, fault_address, writes_applied, fault_snapshot_word

def run_trace_replay_fault_native(fault_at, fault_type='w'):
    import os as _os_native

    if fault_type not in _TRACE_REPLAY_SUPPORTED_FAULT_TYPES:
        return None

    # Writeback mode requires Python-level buffer simulation — the native
    # C# TraceReplayEngine doesn't know about the writeback overlay.
    # Fall back to the Python trace replay path.
    if writeback_active():
        return None

    if not trace_file_bin_path:
        return None
    if not _os_native.path.exists(trace_file_bin_path):
        return None
    # Preserve correctness for legacy calibrations: if erase CSV exists
    # but erase BIN is missing, fall back to Python interleaving logic.
    if erase_trace_file_path and not erase_trace_file_bin_path:
        return None

    engine = ensure_trace_replay_engine()
    if engine is None:
        return None

    fp_t0 = _time.time()
    cpu_ref = monitor.Machine['sysbus.cpu']
    is_non_power_write_fault = fault_type in _TRACE_REPLAY_WRITE_FAULT_TYPES

    # Phase 1: restore flash from cache and replay trace to fault point.
    # No machine Reset needed — reload_images_cached() overwrites full flash,
    # and trace replay is pure memory writes (no CPU execution).
    t_reload = _time.time()
    reload_images_cached()
    if _hash_bypass_active:
        apply_hash_bypass()
    reload_ms = int((_time.time() - t_reload) * 1000)

    # Capture metadata delta snapshot from clean baseline.
    md_pre_snapshot = capture_metadata_delta_snapshot()

    t_replay = _time.time()
    stop_at = int(fault_at) + 1
    page_size = int(backend['data'].PageSize)
    erase_fill = int(backend['data'].EraseFill)
    corruption_seed = 0
    try:
        corruption_seed = int(getattr(backend['data'], 'CorruptionSeed', 0))
    except Exception:
        corruption_seed = 0

    if is_non_power_write_fault:
        if erase_trace_file_bin_path and _os_native.path.exists(erase_trace_file_bin_path):
            writes_applied = int(engine.ReplayWriteFaultWithErases(
                trace_file_bin_path,
                erase_trace_file_bin_path,
                stop_at,
                page_size,
                erase_fill,
                int(_WRITE_FAULT_MODE.get(fault_type, 0)),
                corruption_seed
            ))
        else:
            writes_applied = int(engine.ReplayWriteFault(
                trace_file_bin_path,
                stop_at,
                page_size,
                erase_fill,
                int(_WRITE_FAULT_MODE.get(fault_type, 0)),
                corruption_seed
            ))
    elif erase_trace_file_bin_path and _os_native.path.exists(erase_trace_file_bin_path):
        writes_applied = int(engine.ReplayWithErases(
            trace_file_bin_path,
            erase_trace_file_bin_path,
            stop_at,
            page_size,
            erase_fill
        ))
    else:
        writes_applied = int(engine.Replay(trace_file_bin_path, stop_at))

    fault_injected = bool(engine.LastFaultEncountered)
    fault_address = int(engine.LastFaultAddress)
    actual_writes = max(0, int(fault_at)) if (fault_injected and is_non_power_write_fault) else writes_applied
    faulted_flash = backend['data'].Flash.ReadBytes(0, int(backend['data'].FlashSize))
    fault_snapshot_bytes = to_py_bytes(faulted_flash)
    replay_ms = int((_time.time() - t_replay) * 1000)
    phase1_ms = int((_time.time() - fp_t0) * 1000)

    # Phase 2: reset machine and restore faulted flash for recovery boot.
    # machine Reset zeroes MappedMemory, so we must write back the faulted
    # snapshot captured above, then reload the bootloader ELF.
    t_reset = _time.time()
    restore_flash_and_boot(faulted_flash)
    if _hash_bypass_active:
        apply_hash_bypass()
    reset_ms = int((_time.time() - t_reset) * 1000)

    t_setup = _time.time()
    reset_nvmc_for_recovery()
    setup_ms = int((_time.time() - t_setup) * 1000)

    cpu_ref.IsHalted = False
    arm_vtor_watchpoint()
    t_emu = _time.time()
    p2_status = run_until_done(
        cpu_ref,
        label='fp{}_native_replay_p2'.format(fault_at),
        expect_writes=False,
        zero_writes_is_brick=False,
        wall_timeout=30,
        time_slice=phase2_time_slice,
    )
    emulation_ms = int((_time.time() - t_emu) * 1000)
    disarm_vtor_watchpoint()

    _multiboot_cycles_run = 0
    if fault_injected and is_non_power_write_fault and boot_cycles > 1:
        for extra_cycle in range(1, boot_cycles):
            _multiboot_cycles_run += 1
            monitor.Parse('machine Pause')
            monitor.Parse('machine Reset')
            _bus_load_elf(bootloader_elf)
            if _hash_bypass_active:
                apply_hash_bypass()
            reset_nvmc_for_recovery()
            arm_vtor_watchpoint()
            p2_status = run_until_done(
                cpu_ref,
                label='fp{}_native_replay_cycle{}'.format(fault_at, extra_cycle + 1),
                expect_writes=False,
                zero_writes_is_brick=False,
                wall_timeout=60,
                stop_on_fault=False,
                time_slice=phase2_time_slice,
            )
            disarm_vtor_watchpoint()

    phase2_ms = int((_time.time() - fp_t0) * 1000) - phase1_ms
    total_ms = int((_time.time() - fp_t0) * 1000)

    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    eff_criteria = get_effective_criteria(fault_type)
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=fault_injected, effective_criteria=eff_criteria,
        p2_status=p2_status,
    )
    signals['phase1_ms'] = phase1_ms
    signals['phase2_ms'] = phase2_ms
    signals['reload_ms'] = reload_ms
    signals['replay_ms'] = replay_ms
    signals['reset_ms'] = reset_ms
    signals['setup_ms'] = setup_ms
    signals['emulation_ms'] = emulation_ms
    signals['p2_iters'] = p2_status.get('iters')
    signals['total_ms'] = total_ms
    signals['trace_replay_mode'] = 'native'
    signals['multiboot_cycles_run'] = _multiboot_cycles_run
    signals['phase2_stop_reason'] = p2_status.get('reason')
    signals['phase2_emulated_s'] = p2_status.get('emulated_s')
    if is_non_power_write_fault:
        signals['phase1_continued_after_fault'] = bool(fault_injected)
        signals['phase1_ops_total'] = writes_applied
        signals['trace_replay_semantics'] = 'persisted_flash_reboot'
        signals['fault_snapshot_word'] = fmt_u32(int(engine.LastFaultWordValue))
    if fault_at % 50 == 0:
        log('fp={} native writes={} reload={}ms replay={}ms reset={}ms setup={}ms emu={}ms({}iters) total={}ms outcome={}'.format(
            fault_at, writes_applied, reload_ms, replay_ms, reset_ms, setup_ms,
            emulation_ms, p2_status.get('iters'), total_ms, boot_outcome))

    return _build_fault_result(
        fault_at, fault_type, fault_injected, fault_address,
        actual_writes, signals, boot_outcome=boot_outcome,
        boot_slot=boot_slot, eff_criteria=eff_criteria, p2_status=p2_status,
        followup_label='fp{}_native_followup'.format(fault_at),
        saved_flash=faulted_flash, fault_snapshot_bytes=fault_snapshot_bytes,
        metadata_delta_pre_snapshot=md_pre_snapshot,
    )

def run_trace_replay_fault(fault_at, fault_type='w'):
    global trace_data_loaded, erase_trace_loaded

    if fault_type not in _TRACE_REPLAY_SUPPORTED_FAULT_TYPES:
        return run_execute_fault(fault_at, fault_type=fault_type)
    if writeback_active() and fault_type in _TRACE_REPLAY_WRITE_FAULT_TYPES:
        log('fp={} trace_replay_fallback writeback active for {}'.format(fault_at, fault_type))
        return run_execute_fault(fault_at, fault_type=fault_type)

    native_result = run_trace_replay_fault_native(fault_at, fault_type=fault_type)
    if native_result is not None:
        return native_result

    if trace_data_loaded is None:
        trace_data_loaded = load_trace_data(trace_file_path)
        log('trace_replay: loaded {} write entries from {}'.format(
            len(trace_data_loaded), trace_file_path))
    if erase_trace_loaded is None and erase_trace_file_path:
        import os as _os2
        if _os2.path.exists(erase_trace_file_path):
            erase_trace_loaded = load_erase_trace_data(erase_trace_file_path)
            log('trace_replay: loaded {} erase entries from {}'.format(
                len(erase_trace_loaded), erase_trace_file_path))
        else:
            erase_trace_loaded = []
    if erase_trace_loaded is None:
        erase_trace_loaded = []

    fp_t0 = _time.time()
    cpu_ref = monitor.Machine['sysbus.cpu']
    is_non_power_write_fault = fault_type in _TRACE_REPLAY_WRITE_FAULT_TYPES

    # Phase 1: reconstruct flash state from the clean trace.
    # No machine Reset needed — reload_images_cached() overwrites full flash.
    t_reload = _time.time()
    reload_images_cached()
    if _hash_bypass_active:
        apply_hash_bypass()
    reload_ms = int((_time.time() - t_reload) * 1000)

    # Capture metadata delta snapshot from clean baseline.
    md_pre_snapshot = capture_metadata_delta_snapshot()

    t_replay = _time.time()
    flash_ref = backend['data'].Flash
    flash_base_addr = int(backend['data'].FlashBaseAddress)
    flash_size = int(backend['data'].FlashSize)
    page_size = int(backend['data'].PageSize)
    erase_fill = int(backend['data'].EraseFill)

    fault_snapshot_word = None

    if is_non_power_write_fault:
        faulted_flash, fault_injected, fault_address, writes_applied, fault_snapshot_word = \
            _build_trace_replay_write_fault_snapshot(
                fault_at,
                fault_type,
                flash_base_addr,
                flash_size,
                page_size,
                erase_fill,
            )
        fault_snapshot_bytes = None
        actual_writes = max(0, int(fault_at)) if fault_injected else writes_applied
    elif writeback_active():
        # Writeback mode: only committed writes go to flash.
        writes_applied, fault_injected, fault_address, _wb_discarded = \
            writeback_apply_to_trace_snapshot(
                flash_ref, trace_data_loaded, erase_trace_loaded,
                fault_at, flash_base_addr, page_size,
            )
        actual_writes = writes_applied
        if fault_at % 50 == 0:
            log('fp={} writeback_trace_replay: committed={} discarded={}'.format(
                fault_at, writes_applied, _wb_discarded))
        faulted_flash = flash_ref.ReadBytes(0, flash_size)
        fault_snapshot_bytes = to_py_bytes(faulted_flash)
    else:
        # Direct mode: all writes go to flash (original path).
        import System
        pending_erases = [(wap, foff, esz if esz > 0 else page_size) for foff, wap, esz in erase_trace_loaded]
        pending_erases.sort()
        erase_idx = 0

        writes_applied = 0
        fault_injected = False
        fault_address = 0

        for write_idx, flash_off, value in trace_data_loaded:
            if write_idx > fault_at + 1:
                break

            while erase_idx < len(pending_erases) and pending_erases[erase_idx][0] < write_idx:
                e_wap, e_off, e_sz = pending_erases[erase_idx]
                erase_buf = System.Array.CreateInstance(System.Byte, e_sz)
                for bi in range(e_sz):
                    erase_buf[bi] = 0xFF
                flash_ref.WriteBytes(int(e_off), erase_buf)
                erase_idx += 1

            if write_idx <= fault_at:
                b = System.Array.CreateInstance(System.Byte, 4)
                b[0] = value & 0xFF
                b[1] = (value >> 8) & 0xFF
                b[2] = (value >> 16) & 0xFF
                b[3] = (value >> 24) & 0xFF
                flash_ref.WriteBytes(flash_off, b)
                writes_applied += 1
            elif write_idx == fault_at + 1:
                fault_injected = True
                fault_address = flash_off + flash_base_addr
                break

        while erase_idx < len(pending_erases) and pending_erases[erase_idx][0] <= fault_at:
            e_wap, e_off, e_sz = pending_erases[erase_idx]
            erase_buf = System.Array.CreateInstance(System.Byte, e_sz)
            for bi in range(e_sz):
                erase_buf[bi] = 0xFF
            flash_ref.WriteBytes(int(e_off), erase_buf)
            erase_idx += 1
        actual_writes = writes_applied
        faulted_flash = flash_ref.ReadBytes(0, flash_size)
        fault_snapshot_bytes = to_py_bytes(faulted_flash)

    replay_ms = int((_time.time() - t_replay) * 1000)
    phase1_ms = int((_time.time() - fp_t0) * 1000)

    # Phase 2: reset machine and restore faulted flash for recovery boot.
    # machine Reset zeroes MappedMemory, so we must write back the faulted
    # snapshot captured above, then reload the bootloader ELF.
    t_reset = _time.time()
    restore_flash_and_boot(faulted_flash)
    if _hash_bypass_active:
        apply_hash_bypass()
    reset_ms = int((_time.time() - t_reset) * 1000)

    t_setup = _time.time()
    reset_nvmc_for_recovery()
    setup_ms = int((_time.time() - t_setup) * 1000)

    cpu_ref.IsHalted = False
    arm_vtor_watchpoint()
    t_emu = _time.time()
    p2_status = run_until_done(
        cpu_ref,
        label='fp{}_replay_p2'.format(fault_at),
        expect_writes=False,
        zero_writes_is_brick=False,
        wall_timeout=30,
        time_slice=phase2_time_slice,
    )
    emulation_ms = int((_time.time() - t_emu) * 1000)
    disarm_vtor_watchpoint()

    _multiboot_cycles_run = 0
    if fault_injected and is_non_power_write_fault and boot_cycles > 1:
        for extra_cycle in range(1, boot_cycles):
            _multiboot_cycles_run += 1
            monitor.Parse('machine Pause')
            monitor.Parse('machine Reset')
            _bus_load_elf(bootloader_elf)
            if _hash_bypass_active:
                apply_hash_bypass()
            reset_nvmc_for_recovery()
            arm_vtor_watchpoint()
            p2_status = run_until_done(
                cpu_ref,
                label='fp{}_replay_cycle{}'.format(fault_at, extra_cycle + 1),
                expect_writes=False,
                zero_writes_is_brick=False,
                wall_timeout=60,
                stop_on_fault=False,
                time_slice=phase2_time_slice,
            )
            disarm_vtor_watchpoint()

    phase2_ms = int((_time.time() - fp_t0) * 1000) - phase1_ms
    total_ms = int((_time.time() - fp_t0) * 1000)

    vtor_value = as_int(bus.ReadDoubleWord(0xE000ED08))
    pc_value = as_int(cpu_ref.GetRegisterUnsafe(15))
    eff_criteria = get_effective_criteria(fault_type)
    boot_outcome, boot_slot, signals = evaluate_boot_outcome(
        vtor_value, pc_value, fault_injected=fault_injected, effective_criteria=eff_criteria,
        p2_status=p2_status,
    )
    signals['phase1_ms'] = phase1_ms
    signals['phase2_ms'] = phase2_ms
    signals['reload_ms'] = reload_ms
    signals['replay_ms'] = replay_ms
    signals['reset_ms'] = reset_ms
    signals['setup_ms'] = setup_ms
    signals['emulation_ms'] = emulation_ms
    signals['p2_iters'] = p2_status.get('iters')
    signals['total_ms'] = total_ms
    signals['trace_replay_mode'] = 'python'
    signals['multiboot_cycles_run'] = _multiboot_cycles_run
    signals['phase2_stop_reason'] = p2_status.get('reason')
    signals['phase2_emulated_s'] = p2_status.get('emulated_s')
    if is_non_power_write_fault:
        signals['phase1_continued_after_fault'] = bool(fault_injected)
        signals['phase1_ops_total'] = writes_applied
        signals['trace_replay_semantics'] = 'persisted_flash_reboot'
        if fault_snapshot_word is not None:
            signals['fault_snapshot_word'] = fmt_u32(fault_snapshot_word)
    if fault_at % 50 == 0:
        log('fp={} py_trace_replay writes={} reload={}ms replay={}ms reset={}ms setup={}ms emu={}ms({}iters) total={}ms outcome={}'.format(
            fault_at, writes_applied, reload_ms, replay_ms, reset_ms, setup_ms,
            emulation_ms, p2_status.get('iters'), total_ms, boot_outcome))

    return _build_fault_result(
        fault_at, fault_type, fault_injected, fault_address,
        actual_writes, signals, boot_outcome=boot_outcome,
        boot_slot=boot_slot, eff_criteria=eff_criteria, p2_status=p2_status,
        followup_label='fp{}_python_followup'.format(fault_at),
        saved_flash=faulted_flash, fault_snapshot_bytes=fault_snapshot_bytes,
        metadata_delta_pre_snapshot=md_pre_snapshot,
    )

# ---------------------------------------------------------------------------
# Fault type dispatch: maps fault type codes to runner functions.
#
# Prefix-based codes (e.g. 'm:w', 'h:3:b', 'p2:100:5:w:e') encode
# parameters after the prefix.  Simple codes ('w', 'e', 'b', etc.)
# route to run_execute_fault.  The default path uses the run_fn selected
# at sweep start (trace replay or execute).
# ---------------------------------------------------------------------------

# Fault types that must always use full execute mode (not trace replay)
# because they depend on NVMC peripheral state or PRNG.
_EXECUTE_ONLY_FAULT_TYPES = frozenset(
    ('e', 'a', 'b', 's', 'g', 'x', 'd', 'l', 'r', 't', 'f', 'k',
     'op', 'os', 'od', 'oo',
     'in', 'it', 'ib', 'ic', 'iw')
)


def _dispatch_fault_point(fp, ft, default_run_fn):
    # Dispatch a single fault point to the appropriate runner function.
    #
    # Returns the result dict from the runner.
    parts = None  # IronPython requires pre-declaration for locals used in multiple if-branches
    # --- Prefix-based compound fault types ---
    if ft.startswith('m:'):
        m_type = ft.split(':')[1] if ':' in ft else 'w'
        return run_metadata_fault(fp, fault_type=m_type)

    if ft.startswith('cc:'):
        parts = ft.split(':')
        cc_at = int(parts[1]) if len(parts) > 1 else fp
        cc_type = parts[2] if len(parts) > 2 else 'w'
        return run_confirm_cycle_fault(cc_at, cc_fault_type=cc_type)

    if ft.startswith('h:'):
        parts = ft.split(':')
        h_at = int(parts[1]) if len(parts) > 1 else fp
        h_type = parts[2] if len(parts) > 2 else 'w'
        return run_hook_fault(h_at, hook_fault_type=h_type)

    if ft.startswith('p2:'):
        parts = ft.split(':')
        p1_at = int(parts[1])
        p2_at = int(parts[2])
        p1_type = parts[3] if len(parts) > 3 else 'w'
        p2_type = parts[4] if len(parts) > 4 else 'w'
        return run_phase2_fault(p1_at, p2_at, p1_type, p2_type)

    if ft.startswith('mf:'):
        return run_multi_fault_sequence(decode_multi_fault_sequence_local(ft))

    if ft.startswith('nv:'):
        variant_idx = int(ft.split(':')[1])
        return run_nvs_corruption_fault(variant_idx)

    if ft.startswith('i:'):
        parts = ft.split(':')
        skip_addr = int(parts[1], 0)
        patch_model = parts[2] if len(parts) > 2 else 'nop'
        return run_instruction_skip_fault(skip_addr, patch_model=patch_model)

    if ft.startswith('c:'):
        parts = ft.split(':')
        return run_cascading_fault(int(parts[1]), int(parts[2]))

    # Clustered bit-corruption: 'b:<seed>' sets CorruptionSeed.
    if ft.startswith('b:') and ft[2:].isdigit():
        cseed = int(ft[2:])
        if backend['kind'] == 'fast':
            backend['data'].CorruptionSeed = cseed
        elif backend['kind'] != 'mram':
            backend['data'].Nvm.CorruptionSeed = cseed
        if default_run_fn == run_trace_replay_fault:
            result = default_run_fn(fp, fault_type='b')
        else:
            result = run_execute_fault(fp, fault_type='b')
        if backend['kind'] == 'fast':
            backend['data'].CorruptionSeed = 0
        elif backend['kind'] != 'mram':
            backend['data'].Nvm.CorruptionSeed = 0
        return result

    if default_run_fn == run_trace_replay_fault and ft in _TRACE_REPLAY_SUPPORTED_FAULT_TYPES:
        return default_run_fn(fp, fault_type=ft)

    # --- Simple fault types that require full execute mode ---
    if ft in _EXECUTE_ONLY_FAULT_TYPES:
        return run_execute_fault(fp, fault_type=ft)

    # --- Default: use the pre-selected run function (trace replay or execute) ---
    if default_run_fn == run_state_fault:
        return default_run_fn(fp)
    return default_run_fn(fp, fault_type=ft)


# ---------------------------------------------------------------------------
# Initial NVM fill: MappedMemory starts as 0x00, flash must be 0xFF (erased).
# MRAMMemory erased fill depends on EraseFill property (default 0x00).
# Fill AFTER images were loaded by robot suite — only the areas not covered
# by LoadBinary need the fill.  Reload images after fill to restore them.
# ---------------------------------------------------------------------------
if backend['kind'] in ('fast', 'mram'):
    if update_sequence_enabled:
        # Don't apply phase context or reload images here —
        # ensure_update_sequence_fault_baseline() handles both after
        # running the clean phases to build the pre-fault baseline.
        pass
    else:
        reload_images()

# ---------------------------------------------------------------------------
# Apply initial pre-boot state
# ---------------------------------------------------------------------------
if not update_sequence_enabled:
    apply_pre_boot_state()

# Cache initial flash state for fast restore during sweep.
if not update_sequence_enabled:
    cache_initial_flash()

# ---------------------------------------------------------------------------
# Calibration mode
# ---------------------------------------------------------------------------
if calibration_mode:
    if evaluation_mode == 'state':
        result = {
            'calibration': True,
            'total_writes': total_copy_writes,
            'base_writes': get_total_writes(),
            'setup_writes': pre_boot_write_count,
            'durability_model': durability_model,
        }
        if writeback_active():
            result['writeback_capacity'] = writeback_capacity()
            result['writeback_barriers'] = len(_writeback_barriers)
            result['writeback_erase_flushes'] = writeback_erase_flushes
    else:
        cpu_ref = monitor.Machine['sysbus.cpu']
        disarm_fault()
        if update_sequence_enabled:
            restore_phase1_baseline()
        else:
            monitor.Parse('machine Reset')
            reload_images()
            apply_pre_boot_state()
            if _hash_bypass_active:
                apply_hash_bypass()
        # Force word-level diff for calibration so the count matches sweep.
        # Enable write trace to record (writeIndex, flashOffset) for heuristic.
        reset_nvmc_for_sweep()
        if backend['kind'] == 'fast':
            backend['data'].WriteTraceClear()
            backend['data'].WriteTraceEnabled = True
            # Always capture erase trace — needed for trace replay correctness.
            backend['data'].EraseTraceClear()
            backend['data'].EraseTraceEnabled = True
        log('calibration: starting step (fault_types={})'.format(fault_types_mode))
        base_writes = get_total_writes()
        base_erases = get_total_erases()
        # Disable progress-stall for calibration — the full swap must complete.
        # Long CPU-only phases (hash validation, header parsing) between write
        # bursts can exceed progress_stall_timeout_s in wall time without any
        # write/erase progress, causing premature exit.
        saved_stall = progress_stall_timeout_s
        progress_stall_timeout_s = 0
        cal_wall_timeout = max(600, int(float(run_duration) * 300))
        cal_max_iters = max(500, int(float(run_duration) * 5 / 0.02))
        # Copy-on-boot upgrades can hit a transient VTOR before the final
        # cleanup/copy state settles; give those profiles a short settle window.
        cal_settle = _copy_on_boot_vtor_settle_iters()
        cal_status = run_until_done(cpu_ref, label='calibration',
                                    wall_timeout=cal_wall_timeout,
                                    max_iters=cal_max_iters,
                                    time_slice=calibration_time_slice,
                                    vtor_settle_iters=cal_settle)
        progress_stall_timeout_s = saved_stall
        log('calibration: stop_reason={}'.format(cal_status.get('reason', '?')))
        total_writes = get_total_writes() - base_writes
        total_erases = get_total_erases() - base_erases
        cpu_ref.IsHalted = True

        # Export write trace if available.
        trace_file = None
        trace_file_bin = None
        if backend['kind'] == 'fast' and backend['data'].WriteTraceEnabled:
            backend['data'].WriteTraceEnabled = False
            trace_count = backend['data'].WriteTraceCount
            if trace_count > 0:
                trace_file = result_file.replace('.json', '_trace.csv')
                trace_file_bin = result_file.replace('.json', '_trace.bin')
                trace_data = backend['data'].WriteTraceToString()
                with open(trace_file, 'w') as tf:
                    tf.write('write_index,flash_offset,value\n')
                    with open(trace_file_bin, 'wb') as tfb:
                        trace_bin_count = 0
                        for line in trace_data.strip().split('\n'):
                            parts = line.split(':')
                            if len(parts) == 3:
                                write_idx = int(parts[0]) & 0xFFFFFFFF
                                flash_off = int(parts[1]) & 0xFFFFFFFF
                                value = int(parts[2]) & 0xFFFFFFFF
                                tf.write('{},{},{}\n'.format(write_idx, flash_off, value))
                                tfb.write(struct.pack('<III', write_idx, flash_off, value))
                                trace_bin_count += 1
                            elif len(parts) == 2:
                                write_idx = int(parts[0]) & 0xFFFFFFFF
                                flash_off = int(parts[1]) & 0xFFFFFFFF
                                tf.write('{},{},0\n'.format(write_idx, flash_off))
                                tfb.write(struct.pack('<III', write_idx, flash_off, 0))
                                trace_bin_count += 1
                log('calibration: wrote {} trace entries to {}'.format(trace_count, trace_file))
                log('calibration: wrote {} binary trace entries to {}'.format(trace_bin_count, trace_file_bin))

        # Export erase trace — always captured for trace replay correctness.
        erase_trace_file = None
        erase_trace_file_bin = None
        if backend['kind'] == 'fast':
            backend['data'].EraseTraceEnabled = False
            erase_count = backend['data'].EraseTraceCount
            if erase_count > 0:
                erase_trace_file = result_file.replace('.json', '_erase_trace.csv')
                erase_trace_file_bin = result_file.replace('.json', '_erase_trace.bin')
                erase_data = backend['data'].EraseTraceToString()
                with open(erase_trace_file, 'w') as ef:
                    ef.write('erase_index,flash_offset,writes_at_this_point,erase_size\n')
                    with open(erase_trace_file_bin, 'wb') as efb:
                        erase_bin_count = 0
                        for line in erase_data.strip().split('\n'):
                            parts = line.split(':')
                            if len(parts) >= 4:
                                erase_idx = int(parts[0]) & 0xFFFFFFFF
                                flash_off = int(parts[1]) & 0xFFFFFFFF
                                writes_at = int(parts[2]) & 0xFFFFFFFF
                                erase_sz = int(parts[3]) & 0xFFFFFFFF
                                ef.write('{},{},{},{}\n'.format(erase_idx, flash_off, writes_at, erase_sz))
                                efb.write(struct.pack('<III', writes_at, flash_off, erase_sz))
                                erase_bin_count += 1
                            elif len(parts) >= 3:
                                # Legacy format without erase_size — use PageSize.
                                erase_idx = int(parts[0]) & 0xFFFFFFFF
                                flash_off = int(parts[1]) & 0xFFFFFFFF
                                writes_at = int(parts[2]) & 0xFFFFFFFF
                                fallback_sz = int(backend['data'].PageSize) & 0xFFFFFFFF
                                ef.write('{},{},{},{}\n'.format(erase_idx, flash_off, writes_at, fallback_sz))
                                efb.write(struct.pack('<III', writes_at, flash_off, fallback_sz))
                                erase_bin_count += 1
                log('calibration: wrote {} erase trace entries to {}'.format(erase_count, erase_trace_file))
                log('calibration: wrote {} binary erase entries to {}'.format(erase_bin_count, erase_trace_file_bin))
                log('calibration: {} total erases'.format(total_erases))

        total_i2c_transactions = get_total_i2c_transactions()
        total_otp_blows = get_total_otp_blows()

        result = {
            'calibration': True,
            'total_writes': int(total_writes),
            'total_erases': int(total_erases),
            'total_i2c_transactions': int(total_i2c_transactions),
            'total_otp_blows': int(total_otp_blows),
            'base_writes': int(base_writes),
            'setup_writes': int(pre_boot_write_count),
            'calibration_stop_reason': cal_status.get('reason', '?'),
            'calibration_emulated_s': float(cal_status.get('emulated_s', 0)),
            'calibration_elapsed_s': float(cal_status.get('elapsed_s', 0)),
            'calibration_pc': cal_status.get('pc', '0x00000000'),
            'durability_model': durability_model,
        }
        if writeback_active():
            result['writeback_capacity'] = writeback_capacity()
            result['writeback_barriers'] = len(_writeback_barriers)
            result['writeback_erase_flushes'] = writeback_erase_flushes

            # Barrier audit: analyze write timeline for phase boundaries and
            # barrier coverage.  Phases are detected by domain switches — when
            # writes move from one slot's domain to another.
            if trace_file and total_writes > 0:
                try:
                    _ba_trace = load_trace_data(trace_file)
                    _ba_erase = []
                    if erase_trace_file:
                        import os as _ba_os
                        if _ba_os.path.exists(erase_trace_file):
                            _ba_erase = load_erase_trace_data(erase_trace_file)
                    _ba_flash_base, _ = flash_geometry()
                    _ba_page_size = effective_page_size()

                    # Run full simulation with event recording.
                    _, _, _ba_events = writeback_simulate_buffer(
                        _ba_trace, _ba_erase, total_writes - 1,
                        _ba_flash_base, _ba_page_size, record_events=True,
                    )

                    # Detect phases by scanning writes for domain switches.
                    _ba_phases = []
                    _ba_cur_domain = None
                    _ba_phase_start = 0
                    _ba_phase_writes = 0
                    for _ba_wi, _ba_foff, _ba_val in _ba_trace:
                        _ba_addr = _ba_foff + _ba_flash_base
                        _ba_dom = writeback_domain_for_address(_ba_addr)
                        if _ba_dom is not None and _ba_dom != _ba_cur_domain:
                            if _ba_cur_domain is not None:
                                # Phase boundary: domain switch.
                                # Check if a barrier event occurred between
                                # the previous phase's last write and this one.
                                _ba_has_barrier = False
                                for _ba_ev in _ba_events:
                                    if _ba_phase_start <= _ba_ev['write_index'] <= _ba_wi:
                                        _ba_has_barrier = True
                                        break
                                _ba_phases.append({
                                    'domain': _ba_cur_domain,
                                    'start_write': _ba_phase_start,
                                    'end_write': _ba_wi - 1,
                                    'write_count': _ba_phase_writes,
                                    'barrier_at_end': _ba_has_barrier,
                                })
                            _ba_cur_domain = _ba_dom
                            _ba_phase_start = _ba_wi
                            _ba_phase_writes = 0
                        if _ba_dom is not None:
                            _ba_phase_writes += 1
                    # Final phase.
                    if _ba_cur_domain is not None and _ba_phase_writes > 0:
                        _ba_phases.append({
                            'domain': _ba_cur_domain,
                            'start_write': _ba_phase_start,
                            'end_write': _ba_phase_start + _ba_phase_writes - 1,
                            'write_count': _ba_phase_writes,
                            'barrier_at_end': True,  # end of trace is implicit barrier
                        })
                    _ba_missing = sum(1 for p in _ba_phases if not p.get('barrier_at_end'))
                    barrier_audit = {
                        'total_phases': len(_ba_phases),
                        'phases': _ba_phases,
                        'total_barrier_events': len(_ba_events),
                        'missing_barriers': _ba_missing,
                        'verdict': 'ok' if _ba_missing == 0 else 'missing_barriers',
                    }
                    result['barrier_audit'] = barrier_audit
                    log('calibration: barrier_audit phases={} missing={} verdict={}'.format(
                        len(_ba_phases), _ba_missing, barrier_audit['verdict']))
                except Exception as _ba_exc:
                    log('calibration: barrier_audit failed: {}'.format(_ba_exc))
                    result['barrier_audit'] = {'error': str(_ba_exc)}

        if trace_file:
            result['trace_file'] = trace_file
        if trace_file_bin:
            result['trace_file_bin'] = trace_file_bin
        if erase_trace_file:
            result['erase_trace_file'] = erase_trace_file
        if erase_trace_file_bin:
            result['erase_trace_file_bin'] = erase_trace_file_bin
        # In image_hash mode, compute the exec slot hash after the unfaulted
        # calibration run.  This is the ground-truth hash of what a successful
        # operation produces (bootloaders modify headers/trailers during swap,
        # so the result won't match the original binary file).
        if success_image_hash:
            cal_exec_hash = compute_exec_slot_hash()
            result['calibration_exec_hash'] = cal_exec_hash
            log('calibration: exec slot hash = {}'.format(cal_exec_hash[:16]))
    result = annotate_boot_span_result(result)
    with open(result_file, 'w') as f:
        f.write(_json_dump_text(result))
    log('calibration done: total_writes={}'.format(result.get('total_writes', '?')))

else:
    # -------------------------------------------------------------------
    # Fault sweep (batch or single)
    # -------------------------------------------------------------------
    results = []

    # Select run function: trace replay eliminates Phase 1 emulation.
    import os as _os
    trace_source_exists = (
        (trace_file_bin_path and _os.path.exists(trace_file_bin_path))
        or (trace_file_path and _os.path.exists(trace_file_path))
    )
    use_trace_replay = (
        backend['kind'] == 'fast'
        and evaluation_mode == 'execute'
        and trace_source_exists
    )

    if use_trace_replay:
        run_fn = run_trace_replay_fault
        if trace_file_bin_path and _os.path.exists(trace_file_bin_path):
            log('sweep: using native trace replay mode ({})'.format(trace_file_bin_path))
        else:
            log('sweep: using python trace replay mode ({})'.format(trace_file_path))
    elif evaluation_mode == 'state':
        run_fn = run_state_fault
    else:
        run_fn = run_execute_fault

    for idx, fp in enumerate(fault_points):
        if idx > 0 and evaluation_mode == 'state' and not use_trace_replay:
            reload_images()
            apply_pre_boot_state()
        # Determine fault type for this point.
        ft = 'w'
        if idx < len(fault_type_list):
            ft = fault_type_list[idx]
        if ft == 'f':
            ensure_read_fault_preflight()
        result = annotate_boot_span_result(
            annotate_update_sequence_result(_dispatch_fault_point(fp, ft, run_fn))
        )
        results.append(result)

        # Force .NET GC periodically to prevent memory exhaustion.
        # Every-iteration GC is wasteful; every 10th iteration is sufficient
        # since the main allocations (flash snapshots) are reused via cache.
        if backend['kind'] == 'fast' and idx % 10 == 9:
            import System
            System.GC.Collect()

    # Aggregate timing summary for batch runs.
    if batch_mode and results:
        timing_keys = ['reload_ms', 'replay_ms', 'reset_ms', 'setup_ms', 'emulation_ms', 'followup_ms', 'total_ms', 'p2_iters']
        sums = {}
        maxes = {}
        count = 0
        for r in results:
            s = r.get('signals', {})
            if 'total_ms' not in s:
                continue
            count += 1
            for k in timing_keys:
                v = s.get(k, 0)
                sums[k] = sums.get(k, 0) + v
                maxes[k] = max(maxes.get(k, 0), v)
        if count > 0:
            log('=== TIMING SUMMARY ({} points) ==='.format(count))
            _ms_labels = [
                ('total',     'total_ms'),
                ('reload',    'reload_ms'),
                ('replay',    'replay_ms'),
                ('reset',     'reset_ms'),
                ('setup',     'setup_ms'),
                ('emulation', 'emulation_ms'),
                ('followup',  'followup_ms'),
            ]
            for label, key in _ms_labels:
                log('  {:<10s} sum={}ms  avg={}ms  max={}ms'.format(
                    label + ':', sums.get(key, 0), sums.get(key, 0) // count, maxes.get(key, 0)))
            log('  {:<10s} sum={}    avg={}    max={}'.format(
                'p2_iters:', sums.get('p2_iters', 0), sums.get('p2_iters', 0) // count, maxes.get('p2_iters', 0)))

    # Write results.
    if batch_mode:
        with open(result_file, 'w') as f:
            f.write(_json_dump_text(results))
    else:
        with open(result_file, 'w') as f:
            f.write(_json_dump_text(results[0]))

    log('sweep done: {} fault points'.format(len(results)))

# Halt CPU so Renode exits promptly.
try:
    cpu_ref = monitor.Machine['sysbus.cpu']
    cpu_ref.IsHalted = True
except:
    pass
