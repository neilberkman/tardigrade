# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Success checks shared by the Renode sweep and standalone reproducer."""


DEFAULT_BOOT_OBSERVATION_SLICES = 200


def has_image_scoped_checks(config):
    return any(
        isinstance(check, dict) and (
            check.get('image') is not None
            or check.get('symbol') is not None
            or bool(check.get('addresses'))
        )
        for kind in ('memory_checks', 'config_checks')
        if isinstance(config.get(kind), list)
        for check in config[kind]
    )


def match_allowed_image(digest, allowed_hashes):
    digest = str(digest or '').strip().lower()
    if not digest:
        return None
    for entry in allowed_hashes:
        if digest == str(entry.get('sha256', '')).strip().lower():
            return str(entry.get('name', '')).strip() or None
    return None


def evaluate_success_checks(config, bus, as_int, fmt_u32, matched_image=None,
                            sram_start=0, sram_end=0, transport_error=None,
                            mram_uncorrectable_address=None):
    """Read global checks and checks for the exact allowed image digest."""
    memory_specs = config.get('memory_checks', [])
    config_specs = config.get('config_checks', [])
    integrity_enabled = bool(config.get('bootloader_integrity', False))
    requested = bool(
        memory_specs
        or config_specs
        or integrity_enabled
        or transport_error
    )
    observations = {
        'contract_version': 1,
        'requested': requested,
        'all_ok': True,
        'memory_checks_ok': True,
        'config_checks_ok': True,
        'bootloader_integrity_ok': True,
        'memory_checks': [],
        'config_checks': [],
        'config_values': {},
    }
    if matched_image is not None:
        observations['matched_image'] = matched_image
    if transport_error:
        observations['transport_error'] = transport_error
        observations['all_ok'] = False

    def _resolve_spec_target(spec, detail):
        image = spec.get('image')
        addresses = spec.get('addresses')
        if image is not None:
            if image != matched_image:
                return None
            detail['image'] = image
        elif isinstance(addresses, dict):
            if matched_image not in addresses:
                return None
            detail['image'] = matched_image
        if spec.get('symbol') is not None:
            detail['symbol'] = str(spec['symbol'])
        if isinstance(addresses, dict) and matched_image in addresses:
            raw_addr = addresses[matched_image]
        else:
            raw_addr = spec['address']
        return int(str(raw_addr), 0) if isinstance(raw_addr, str) else int(raw_addr)

    if not isinstance(memory_specs, list):
        observations['memory_checks_error'] = 'memory_checks is not a list'
        observations['memory_checks_ok'] = False
        memory_specs = []
    for index, spec in enumerate(memory_specs):
        detail = {'index': index, 'ok': False}
        try:
            if not isinstance(spec, dict):
                raise ValueError('check is not a mapping')
            address = _resolve_spec_target(spec, detail)
            if address is None:
                continue
            detail['address'] = '0x{:X}'.format(address)
            op = str(spec.get('op', 'eq')).strip().lower()
            width = int(spec.get('width', 4))
            read = getattr(bus, {1: 'ReadByte', 2: 'ReadWord', 4: 'ReadDoubleWord'}[width])
            value_mask = (1 << (8 * width)) - 1
            mask = int(spec.get('mask', 0xFFFFFFFF)) & value_mask
            actual = as_int(read(address)) & value_mask
            if 'width' in spec:
                detail['width'] = width
            masked_actual = actual & mask
            expected = spec.get('expected_value')
            if op == 'nonzero':
                ok = masked_actual != 0
            else:
                if expected is None:
                    raise ValueError('expected_value is missing for op {}'.format(op))
                masked_expected = int(expected) & mask
                if op == 'eq':
                    ok = masked_actual == masked_expected
                elif op == 'ne':
                    ok = masked_actual != masked_expected
                elif op == 'ge':
                    ok = masked_actual >= masked_expected
                elif op == 'le':
                    ok = masked_actual <= masked_expected
                else:
                    raise ValueError('unsupported op {}'.format(op))
                detail['expected'] = int(expected) & 0xFFFFFFFF
                detail['expected_masked'] = masked_expected
            detail.update({
                'actual': actual,
                'actual_hex': fmt_u32(actual),
                'actual_masked': masked_actual,
                'mask': mask,
                'op': op,
                'ok': bool(ok),
            })
            marked_word_addr = (
                mram_uncorrectable_address(address) if mram_uncorrectable_address is not None else None
            )
            if marked_word_addr is not None:
                detail['uncorrectable'] = True
                detail['uncorrectable_word_address'] = marked_word_addr
        except Exception as exc:
            detail['error'] = str(exc)
            ok = False
        if not ok:
            observations['memory_checks_ok'] = False
        observations['memory_checks'].append(detail)

    if not isinstance(config_specs, list):
        observations['config_checks_error'] = 'config_checks is not a list'
        observations['config_checks_ok'] = False
        config_specs = []
    for index, spec in enumerate(config_specs):
        detail = {'index': index, 'ok': False}
        try:
            if not isinstance(spec, dict):
                raise ValueError('check is not a mapping')
            address = _resolve_spec_target(spec, detail)
            if address is None:
                continue
            detail['address'] = '0x{:X}'.format(address)
            actual = as_int(bus.ReadDoubleWord(address)) & 0xFFFFFFFF
            ok = True
            failures = []
            expected = spec.get('expected')
            if expected is not None and actual != (int(expected) & 0xFFFFFFFF):
                ok = False
                failures.append('expected')
            if bool(spec.get('nonzero', False)) and actual == 0:
                ok = False
                failures.append('nonzero')
            range_min = spec.get('range_min')
            range_max = spec.get('range_max')
            if range_min is not None and actual < int(range_min):
                ok = False
                failures.append('range_min')
            if range_max is not None and actual > int(range_max):
                ok = False
                failures.append('range_max')
            mask = spec.get('mask')
            expected_masked = spec.get('expected_masked')
            if mask is not None or expected_masked is not None:
                if mask is None or expected_masked is None:
                    raise ValueError('mask and expected_masked must be configured together')
                if (actual & int(mask)) != (int(expected_masked) & int(mask)):
                    ok = False
                    failures.append('expected_masked')
            address_key = detail['address']
            observations['config_values'][address_key] = actual
            detail.update({
                'actual': actual,
                'actual_hex': fmt_u32(actual),
                'expected': expected,
                'nonzero': bool(spec.get('nonzero', False)),
                'range_min': range_min,
                'range_max': range_max,
                'mask': mask,
                'expected_masked': expected_masked,
                'failed_constraints': failures,
                'ok': bool(ok),
            })
        except Exception as exc:
            detail['error'] = str(exc)
            ok = False
        if not ok:
            observations['config_checks_ok'] = False
        observations['config_checks'].append(detail)

    if integrity_enabled:
        integrity = {'enabled': True, 'ok': False}
        try:
            region = config.get('bootloader_region')
            if not isinstance(region, dict):
                raise ValueError('bootloader_region is missing')
            base = int(region['base'])
            size = int(region['size'])
            if size < 8:
                raise ValueError('bootloader_region is smaller than 8 bytes')
            initial_sp = as_int(bus.ReadDoubleWord(base)) & 0xFFFFFFFF
            reset_vector = as_int(bus.ReadDoubleWord(base + 4)) & 0xFFFFFFFF
            reset_pc = reset_vector & ~1
            sp_ok = sram_start <= initial_sp <= sram_end
            reset_thumb_ok = (reset_vector & 1) == 1
            reset_ok = reset_thumb_ok and base <= reset_pc < (base + size)
            integrity.update({
                'region_base': '0x{:X}'.format(base),
                'region_size': size,
                'initial_sp': initial_sp,
                'initial_sp_hex': fmt_u32(initial_sp),
                'initial_sp_ok': sp_ok,
                'reset_vector': reset_vector,
                'reset_vector_hex': fmt_u32(reset_vector),
                'reset_pc': reset_pc,
                'reset_pc_hex': fmt_u32(reset_pc),
                'reset_thumb_ok': reset_thumb_ok,
                'reset_vector_ok': reset_ok,
                'ok': bool(sp_ok and reset_ok),
                'reason': (
                    'ok'
                    if sp_ok and reset_ok
                    else 'invalid initial SP or reset vector'
                ),
            })
        except Exception as exc:
            integrity['error'] = str(exc)
        observations['bootloader_integrity'] = integrity
        observations['bootloader_integrity_ok'] = bool(integrity.get('ok'))

    observations['all_ok'] = bool(
        observations['all_ok']
        and observations['memory_checks_ok']
        and observations['config_checks_ok']
        and observations['bootloader_integrity_ok']
    )
    return observations
