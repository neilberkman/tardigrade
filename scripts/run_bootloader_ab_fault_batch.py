"""In-process Renode runner for the generic A/B OTA fault campaign.

This file intentionally uses Python 2-compatible syntax because released
Renode builds may execute it with IronPython.  The surrounding ``.resc`` file
supplies ``monitor`` and executes this module in Renode's Python context.
"""

import json
import os
import struct
import sys

from System import Array, Byte


def _as_int(value):
    try:
        return int(value) & 0xFFFFFFFF
    except Exception:
        return int(str(value), 0) & 0xFFFFFFFF


def _as_long(value):
    try:
        return int(value)
    except Exception:
        return int(str(value), 0)


def _get_text(name, default=''):
    try:
        value = str(monitor.GetVariable(name)).strip()
    except Exception:
        value = ''
    return value if value else default


def _get_long(name, default=0):
    value = _get_text(name, '')
    return _as_long(value) if value else int(default)


def _get_float(name, default):
    value = _get_text(name, '')
    try:
        result = float(value) if value else float(default)
    except Exception:
        result = float(default)
    return result


def _get_bool(name, default=False):
    value = _get_text(name, '')
    if not value:
        return bool(default)
    return value.lower() in ('1', 'true', 'yes', 'on')


def _fmt_u32(value):
    return '0x{0:08X}'.format(_as_int(value))


def _path_token(path):
    path = str(path)
    if any(ch.isspace() for ch in path):
        return '@"{}"'.format(path.replace('"', '\\"'))
    return '@' + path


def _atomic_write_json(path, payload):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    temp_path = path + '.tmp'
    with open(temp_path, 'w') as stream:
        stream.write(json.dumps(payload, sort_keys=True))
        stream.flush()
    if os.path.exists(path):
        os.remove(path)
    os.rename(temp_path, path)


repo_root = _get_text('repo_root')
if not repo_root:
    raise Exception('repo_root is required')
scripts_dir = os.path.join(repo_root, 'scripts')
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from layout_validation import validate_load_plan
from boot_observation import poll_boot


result_file = _get_text('result_file', 'bootloader_ab_fault_result.json')
fault_points_csv = _get_text('fault_points_csv')
single_fault_at = _get_long('fault_at', 0)
if fault_points_csv:
    fault_points = [
        _as_long(item.strip())
        for item in fault_points_csv.split(',')
        if item.strip()
    ]
else:
    fault_points = [single_fault_at]
batch_mode = bool(fault_points_csv)

if not fault_points:
    raise Exception('fault_points_csv did not contain a point')
if batch_mode:
    if fault_points[0] != -1:
        raise Exception('batch campaigns must put the clean control (-1) first')
    if any(point < 0 for point in fault_points[1:]):
        raise Exception('only the first batch point may be the clean control')
    if len(set(fault_points)) != len(fault_points):
        raise Exception('batch fault points must be unique')

total_writes = _get_long('total_writes', 0)
include_metadata_faults = _get_bool('include_metadata_faults', False)
evaluation_mode = _get_text('evaluation_mode', 'execute').lower()
boot_mode = _get_text('boot_mode', 'direct').lower()
write_granularity = _get_long('write_granularity', 0)
slot_a_base = _get_long('slot_a_base', 0)
slot_b_base = _get_long('slot_b_base', 0)
slot_size = _get_long('slot_size', 0)
ota_header_size = _get_long('ota_header_size', 0)
meta_base_0 = _get_long('meta_base_0', 0)
meta_base_1 = _get_long('meta_base_1', 0)
meta_size = _get_long('meta_size', 0)
bootloader_entry = _get_long('bootloader_entry', 0)
nvm_ctrl_path = _get_text('nvm_ctrl_path', 'sysbus.nvm_ctrl')

slot_a_image_file = _get_text('slot_a_image_file')
slot_b_image_file = _get_text('slot_b_image_file')
platform_repl = _get_text('platform_repl')
firmware_elf = _get_text('firmware_elf')
bootloader_elf = _get_text('bootloader_elf')
boot_meta_bin = _get_text('boot_meta_bin')
boot_meta_load_addr = _get_long('boot_meta_load_addr', 0)

expected_control_slot = _get_text('expected_control_slot').upper()
boot_marker_addr = _get_long('boot_marker_addr', 0)
boot_marker_value = _get_long('boot_marker_value', 0) & 0xFFFFFFFF
boot_marker_other_value = _get_long('boot_marker_other_value', 0) & 0xFFFFFFFF
observation_timeout_s = _get_float('boot_observation_timeout_s', 20.0)
poll_interval_s = _get_float('boot_poll_interval_s', 0.02)
wall_timeout_s = _get_float('boot_wall_timeout_s', 180.0)
pre_boot_writes_raw = _get_text('pre_boot_writes')
pre_boot_writes = []
if pre_boot_writes_raw:
    for item in pre_boot_writes_raw.split(','):
        address_text, separator, value_text = item.partition('=')
        if not separator:
            raise Exception('invalid pre_boot_writes entry: {}'.format(item))
        pre_boot_writes.append((_as_long(address_text), _as_long(value_text)))

trace_execution = _get_bool('trace_execution', False)
trace_file = _get_text('trace_file')

if evaluation_mode not in ('execute', 'state'):
    raise Exception("evaluation_mode must be 'execute' or 'state'")
if boot_mode not in ('direct', 'copy', 'swap'):
    raise Exception("boot_mode must be 'direct', 'copy', or 'swap'")
if write_granularity <= 0:
    raise Exception('write_granularity must be positive')
if slot_size <= 0 or slot_a_base == slot_b_base:
    raise Exception('distinct slot bases and a positive slot size are required')
if total_writes <= 0:
    raise Exception('total_writes must be positive')
if ota_header_size < 0 or ota_header_size >= slot_size:
    raise Exception('ota_header_size must fall inside each slot')
if observation_timeout_s <= 0 or poll_interval_s <= 0 or wall_timeout_s <= 0:
    raise Exception('boot observation budgets must be positive')

if batch_mode:
    if evaluation_mode != 'execute':
        raise Exception('batch campaigns require execute evaluation mode')
    if not platform_repl or not bootloader_elf:
        raise Exception('batch campaigns require platform_repl and bootloader_elf')
    if expected_control_slot not in ('A', 'B'):
        raise Exception("expected_control_slot must be 'A' or 'B'")
    invalid_sentinels = (0, 0xFFFFFFFF)
    if boot_marker_addr == 0:
        raise Exception('a boot marker address is required for the clean control')
    if boot_marker_value in invalid_sentinels:
        raise Exception('the clean-control marker sentinel must be nonzero and non-erased')
    if boot_marker_other_value in invalid_sentinels:
        raise Exception('the alternate marker sentinel must be nonzero and non-erased')
    if boot_marker_value == boot_marker_other_value:
        raise Exception('slot marker sentinels must be distinct')


def _file_bytes(path):
    if not path:
        return b''
    with open(path, 'rb') as stream:
        return stream.read()


slot_a_source = _file_bytes(slot_a_image_file)
slot_b_source = _file_bytes(slot_b_image_file)
if slot_a_source and len(slot_a_source) > slot_size:
    raise Exception('slot A image exceeds the declared slot')
if slot_b_source and len(slot_b_source) > slot_size:
    raise Exception('slot B image exceeds the declared slot')


def _validate_layout():
    nvm_base = _get_long('nvm_base', min(slot_a_base, slot_b_base, bootloader_entry))
    nvm_size = _get_long('nvm_size', 0)
    if nvm_size <= 0:
        upper = max(slot_a_base + slot_size, slot_b_base + slot_size)
        if meta_size > 0:
            upper = max(upper, meta_base_0 + meta_size, meta_base_1 + meta_size)
        nvm_size = upper - nvm_base

    metadata = []
    if meta_size > 0:
        metadata.append({'name': 'metadata_primary', 'base': meta_base_0, 'size': meta_size})
        if meta_base_1 != meta_base_0:
            metadata.append({'name': 'metadata_secondary', 'base': meta_base_1, 'size': meta_size})

    loads = []
    if slot_a_image_file:
        loads.append({
            'name': 'slot_a_image',
            'path': slot_a_image_file,
            'address': slot_a_base,
            'slot': 'A',
        })
    if slot_b_image_file:
        loads.append({
            'name': 'slot_b_image',
            'path': slot_b_image_file,
            'address': slot_b_base,
            'slot': 'B',
        })

    plan = {
        'version': 1,
        'nvm': {'base': nvm_base, 'size': nvm_size},
        'bootloader': {'elf': bootloader_elf},
        'slots': {
            'A': {'base': slot_a_base, 'size': slot_size, 'write_full': True},
            'B': {'base': slot_b_base, 'size': slot_size, 'write_full': True},
        },
        'metadata': metadata,
        'loads': loads,
    }
    validate_load_plan(plan)


if bootloader_elf:
    _validate_layout()


def _load_machine():
    monitor.Parse('mach clear')
    monitor.Parse('mach create')
    monitor.Parse('machine LoadPlatformDescription {}'.format(_path_token(platform_repl)))
    if firmware_elf:
        monitor.Parse('sysbus LoadELF {}'.format(_path_token(firmware_elf)))
    if boot_meta_bin:
        monitor.Parse(
            'sysbus LoadBinary {} 0x{:X}'.format(
                _path_token(boot_meta_bin), boot_meta_load_addr
            )
        )
    monitor.Parse('sysbus LoadELF {}'.format(_path_token(bootloader_elf)))

    point_bus = monitor.Machine.SystemBus
    point_cpu = monitor.Machine['sysbus.cpu']
    point_ctrl = None
    if nvm_ctrl_path:
        try:
            point_ctrl = monitor.Machine[nvm_ctrl_path]
        except Exception:
            point_ctrl = None
    return point_bus, point_cpu, point_ctrl


def _read_chunk(bus, address, size):
    raw = bus.ReadBytes(address, size)
    return bytes(bytearray([(int(item) & 0xFF) for item in raw]))


def _write_chunk(bus, address, chunk):
    data = Array[Byte]([int(item) & 0xFF for item in bytearray(chunk)])
    bus.WriteBytes(address, data, 0, len(data))


def _fill_region(bus, address, size, value):
    block_size = 4096
    block = bytes(bytearray([value & 0xFF] * block_size))
    offset = 0
    while offset < size:
        count = min(block_size, size - offset)
        _write_chunk(bus, address + offset, block[:count])
        offset += count


def _padded_chunk(source, offset, size, fill=0xFF):
    chunk = source[offset:offset + size]
    if len(chunk) < size:
        chunk += bytes(bytearray([fill] * (size - len(chunk))))
    return chunk


def _slot_for_pc(pc_value):
    pc = _as_int(pc_value) & (~1)
    a_start = slot_a_base + ota_header_size
    b_start = slot_b_base + ota_header_size
    if a_start <= pc < slot_a_base + slot_size:
        return 'A'
    if b_start <= pc < slot_b_base + slot_size:
        return 'B'
    return None


def _slot_for_vtor(vtor_value):
    value = _as_int(vtor_value)
    if slot_a_base <= value < slot_a_base + slot_size:
        return 'A'
    if slot_b_base <= value < slot_b_base + slot_size:
        return 'B'
    return None


def _slot_vector_valid(bus, base):
    vector_base = base + ota_header_size
    sp = _as_int(bus.ReadDoubleWord(vector_base))
    reset_vector = _as_int(bus.ReadDoubleWord(vector_base + 4))
    reset_pc = reset_vector & (~1)
    return (
        0x20000000 <= sp <= 0x20040000
        and (reset_vector & 1) == 1
        and vector_base <= reset_pc < base + slot_size
    )


def _observe_boot(bus, cpu, is_control):
    def run_slice(duration):
        monitor.Parse('emulation RunFor "{:.6f}"'.format(duration))

    return poll_boot(
        run_slice=run_slice,
        read_pc=lambda: _as_int(cpu.GetRegisterUnsafe(15)),
        read_vtor=lambda: _as_int(bus.ReadDoubleWord(0xE000ED08)),
        read_marker=(
            (lambda: _as_int(bus.ReadDoubleWord(boot_marker_addr)))
            if boot_marker_addr else None
        ),
        classify_pc=_slot_for_pc,
        classify_vtor=_slot_for_vtor,
        is_control=is_control,
        expected_slot=expected_control_slot,
        marker_value=boot_marker_value,
        emulated_timeout_s=observation_timeout_s,
        poll_interval_s=poll_interval_s,
        wall_timeout_s=wall_timeout_s,
    )


def _run_point(point):
    is_control = point < 0
    bus, cpu, ctrl = _load_machine() if batch_mode else (
        monitor.Machine.SystemBus,
        monitor.Machine['sysbus.cpu'],
        None,
    )
    if not batch_mode and nvm_ctrl_path:
        try:
            ctrl = monitor.Machine[nvm_ctrl_path]
        except Exception:
            ctrl = None

    state = {
        'index': 0,
        'faulted': False,
        'fault_address': 0,
        'fault_model': None,
    }

    # Start every point from explicit erased slot contents.  Machine
    # recreation prevents prior markers, RAM, controller counters, and other
    # target state from leaking between points.
    _fill_region(bus, slot_a_base, slot_size, 0xFF)
    _fill_region(bus, slot_b_base, slot_size, 0xFF)

    if slot_a_source:
        for offset in range(0, slot_size, write_granularity):
            _write_chunk(
                bus,
                slot_a_base + offset,
                _padded_chunk(slot_a_source, offset, write_granularity),
            )

    source = slot_b_source if slot_b_source else slot_a_source
    max_slot_writes = (slot_size + write_granularity - 1) // write_granularity
    write_count = min(total_writes, max_slot_writes)

    def inject_partial_write(address, intended):
        half = max(1, write_granularity // 2)
        corrupted = intended[:half] + bytes(bytearray([0] * (write_granularity - half)))
        _write_chunk(bus, address, corrupted)
        model = 'deterministic_low_half'
        if ctrl is not None and hasattr(ctrl, 'InjectPartialWrite'):
            ctrl.InjectPartialWrite(address)
            model = 'controller_low_half'
        state['faulted'] = True
        state['fault_address'] = address
        state['fault_model'] = model

    def maybe_write_chunk(address, chunk):
        if state['faulted']:
            return False
        if not is_control and state['index'] == point:
            inject_partial_write(address, chunk)
            return False
        _write_chunk(bus, address, chunk)
        state['index'] += 1
        return True

    for index in range(write_count):
        offset = index * write_granularity
        if source:
            chunk = _padded_chunk(source, offset, write_granularity)
        else:
            chunk = _read_chunk(bus, slot_a_base + offset, write_granularity)
        if not maybe_write_chunk(slot_b_base + offset, chunk):
            break

    meta_blob = bytearray()
    if meta_size > 0:
        for index in range(meta_size):
            meta_blob.append(_as_int(bus.ReadByte(meta_base_0 + index)) & 0xFF)

    def write_metadata_replica(base):
        for offset in range(0, meta_size, 4):
            chunk = bytes(meta_blob[offset:offset + 4])
            if len(chunk) < 4:
                chunk += bytes(bytearray([0xFF] * (4 - len(chunk))))
            if include_metadata_faults:
                fault_chunk = _padded_chunk(chunk, 0, write_granularity)
                if not maybe_write_chunk(base + offset, fault_chunk):
                    return False
            else:
                bus.WriteDoubleWord(base + offset, struct.unpack('<I', chunk)[0])
        return True

    if meta_size > 0 and write_metadata_replica(meta_base_1):
        write_metadata_replica(meta_base_0)

    for address, value in pre_boot_writes:
        bus.WriteDoubleWord(address, value & 0xFFFFFFFF)

    fault_diag = {}
    if state['faulted']:
        address = int(state['fault_address'])
        fault_diag['fault_address'] = _fmt_u32(address)
        fault_diag['corrupted_bytes'] = ''.join(
            '{:02X}'.format(item)
            for item in bytearray(_read_chunk(bus, address, write_granularity))
        )
        if slot_b_base <= address < slot_b_base + slot_size:
            offset = address - slot_b_base
            fault_diag['region'] = (
                'image_header' if offset < ota_header_size else
                'vector_table' if offset < ota_header_size + 8 else
                'payload'
            )
            fault_diag['offset_in_slot'] = offset
        elif meta_base_0 <= address < meta_base_0 + meta_size:
            fault_diag['region'] = 'metadata_primary'
        elif meta_base_1 <= address < meta_base_1 + meta_size:
            fault_diag['region'] = 'metadata_secondary'
        else:
            fault_diag['region'] = 'outside_declared_regions'

    slot_a_valid = _slot_vector_valid(bus, slot_a_base)
    slot_b_valid = _slot_vector_valid(bus, slot_b_base)

    observation = None
    boot_slot = None
    if evaluation_mode == 'execute':
        if trace_execution:
            point_trace = trace_file
            if batch_mode and point_trace:
                stem, extension = os.path.splitext(point_trace)
                point_trace = '{}_{}{}'.format(
                    stem,
                    'control' if is_control else 'f{}'.format(point),
                    extension,
                )
            if point_trace:
                trace_parent = os.path.dirname(os.path.abspath(point_trace))
                if trace_parent and not os.path.isdir(trace_parent):
                    os.makedirs(trace_parent)
                escaped = point_trace.replace('\\', '\\\\').replace('"', '\\"')
                monitor.Parse(
                    'sysbus.cpu CreateExecutionTracing "tracer" "{}" PC'.format(escaped)
                )
                monitor.Parse('tracer TraceFormat "PC"')

        for offset in range(0, 0x100, 4):
            bus.WriteDoubleWord(
                offset,
                _as_int(bus.ReadDoubleWord(bootloader_entry + offset)),
            )
        try:
            cpu.VectorTableOffset = bootloader_entry
        except Exception:
            pass
        monitor.Parse('machine Reset')
        observation = _observe_boot(bus, cpu, is_control)
        boot_slot = observation.get('pc_sticky_slot')
    else:
        if boot_mode == 'swap':
            boot_slot = 'A' if slot_a_valid else None
        else:
            boot_slot = 'B' if slot_b_valid else ('A' if slot_a_valid else None)

    if observation and observation.get('infrastructure_error'):
        boot_outcome = 'infra_error'
    elif boot_slot is None:
        boot_outcome = 'no_boot'
    elif is_control and boot_slot != expected_control_slot:
        boot_outcome = 'wrong_pc'
    elif is_control and not observation.get('marker_ok', False):
        boot_outcome = 'wrong_image'
    else:
        boot_outcome = 'success'

    control_passed = None
    if is_control:
        control_passed = bool(
            boot_outcome == 'success'
            and boot_slot == expected_control_slot
            and observation is not None
            and observation.get('pc_sticky_slot') == expected_control_slot
            and observation.get('marker_ok')
            and observation.get('marker_actual') == _fmt_u32(boot_marker_value)
        )

    result = {
        'fault_at': int(point),
        'is_control': bool(is_control),
        'fault_injected': bool(state['faulted']),
        'boot_outcome': boot_outcome,
        'boot_slot': boot_slot,
        'control_passed': control_passed,
        'fault_diagnostics': fault_diag,
        'signals': observation or {},
        'nvm_state': {
            'evaluation_mode': evaluation_mode,
            'boot_mode': boot_mode,
            'slot_a_base': _fmt_u32(slot_a_base),
            'slot_b_base': _fmt_u32(slot_b_base),
            'slot_size': int(slot_size),
            'write_granularity': int(write_granularity),
            'ota_header_size': int(ota_header_size),
            'meta_base_0': _fmt_u32(meta_base_0),
            'meta_base_1': _fmt_u32(meta_base_1),
            'meta_size': int(meta_size),
            'write_index': int(state['index']),
            'faulted': bool(state['faulted']),
            'fault_model': state['fault_model'],
            'fault_address': _fmt_u32(state['fault_address']),
            'slot_a_valid': bool(slot_a_valid),
            'slot_b_valid': bool(slot_b_valid),
        },
    }
    if observation and observation.get('infrastructure_error'):
        result['error'] = observation.get('infrastructure_error')
    return result


payload = {
    'schema_version': 1,
    'aborted': False,
    'abort_reason': None,
    'control_passed': None,
    'results': [],
}

for fault_point in fault_points:
    point_result = _run_point(fault_point)
    payload['results'].append(point_result)
    if fault_point < 0:
        payload['control_passed'] = bool(point_result.get('control_passed'))
        if not payload['control_passed']:
            payload['aborted'] = True
            payload['abort_reason'] = (
                'clean control failed: outcome={} slot={} expected_slot={} '
                'pc={} marker={} expected_marker={}'.format(
                    point_result.get('boot_outcome'),
                    point_result.get('boot_slot'),
                    expected_control_slot,
                    point_result.get('signals', {}).get('pc_sticky'),
                    point_result.get('signals', {}).get('marker_actual'),
                    _fmt_u32(boot_marker_value),
                )
            )
            _atomic_write_json(result_file, payload)
            break
    elif point_result.get('boot_outcome') == 'infra_error':
        payload['aborted'] = True
        payload['abort_reason'] = point_result.get('error', 'fault point infrastructure failure')
        _atomic_write_json(result_file, payload)
        break
    _atomic_write_json(result_file, payload)

if batch_mode:
    _atomic_write_json(result_file, payload)
else:
    _atomic_write_json(result_file, payload['results'][0])
