"""Helpers for Thumb instruction-width aware instruction-skip planning."""

try:
    from functools import lru_cache
except ImportError:
    def lru_cache(maxsize=None):  # type: ignore[override]
        def decorator(func):
            return func
        return decorator


def is_thumb_32bit_first_halfword(halfword):
    """Return True when *halfword* starts a 32-bit Thumb instruction."""
    top5 = (int(halfword) >> 11) & 0x1F
    return top5 in (0b11101, 0b11110, 0b11111)


def thumb_instruction_halfword_width(halfword):
    """Return instruction width in 16-bit halfwords."""
    return 2 if is_thumb_32bit_first_halfword(halfword) else 1


def is_thumb_second_halfword(read_halfword, addr):
    """Return True when *addr* points at the second halfword of a 32-bit instruction."""
    if int(addr) < 2:
        return False
    try:
        prev = int(read_halfword(int(addr) - 2)) & 0xFFFF
    except Exception:
        return False
    return is_thumb_32bit_first_halfword(prev)


def instruction_sequence_fits(read_halfword, start_addr, region_end, instruction_count):
    """Return True when *instruction_count* whole instructions fit before *region_end*."""
    cur = int(start_addr)
    stop = int(region_end)
    count = max(1, int(instruction_count))
    for _ in range(count):
        if cur + 2 > stop:
            return False
        try:
            first_halfword = int(read_halfword(cur)) & 0xFFFF
        except Exception:
            return False
        cur += thumb_instruction_halfword_width(first_halfword) * 2
        if cur > stop:
            return False
    return True


def enumerate_instruction_skip_addresses(read_halfword, region_start, region_end, skip_count=1):
    """Enumerate valid instruction-skip start addresses for a Thumb code region."""
    addrs = []
    start = int(region_start)
    end = int(region_end)
    count = max(1, int(skip_count))
    addr = start
    while addr < end:
        try:
            first_halfword = int(read_halfword(addr)) & 0xFFFF
        except Exception:
            break
        if instruction_sequence_fits(read_halfword, addr, end, count):
            addrs.append(addr)
        addr += thumb_instruction_halfword_width(first_halfword) * 2
    return addrs


def build_instruction_skip_patch_plan(
    read_halfword,
    skip_addr,
    skip_count,
    patch_model="nop",
    branch_inverter=None,
):
    """Plan the halfword patch set for an instruction-skip fault."""
    original_halfwords = []
    patched_halfwords = []
    patched_addresses = []
    model = str(patch_model or "nop").strip().lower() or "nop"
    count = max(1, int(skip_count))

    if model not in ("nop", "branch_invert"):
        return {
            "supported": False,
            "reason": "unknown_patch_model",
            "model": model,
            "original_halfwords": original_halfwords,
            "patched_halfwords": patched_halfwords,
            "patched_addresses": patched_addresses,
            "instruction_count": count,
        }
    if model == "branch_invert" and count != 1:
        return {
            "supported": False,
            "reason": "branch_invert_requires_single_halfword",
            "model": model,
            "original_halfwords": original_halfwords,
            "patched_halfwords": patched_halfwords,
            "patched_addresses": patched_addresses,
            "instruction_count": count,
        }

    cur_addr = int(skip_addr)
    try:
        if model == "nop":
            for _ in range(count):
                first_halfword = int(read_halfword(cur_addr)) & 0xFFFF
                halfword_width = thumb_instruction_halfword_width(first_halfword)
                for halfword_index in range(halfword_width):
                    addr = cur_addr + halfword_index * 2
                    orig = int(read_halfword(addr)) & 0xFFFF
                    patched_addresses.append(addr)
                    original_halfwords.append(orig)
                    patched_halfwords.append(0xBF00)
                cur_addr += halfword_width * 2
        else:
            orig = int(read_halfword(cur_addr)) & 0xFFFF
            patched = None if branch_inverter is None else branch_inverter(orig)
            if patched is None:
                return {
                    "supported": False,
                    "reason": "branch_invert_not_supported_for_instruction",
                    "model": model,
                    "original_halfwords": [orig],
                    "patched_halfwords": patched_halfwords,
                    "patched_addresses": patched_addresses,
                    "instruction_count": count,
                }
            patched_addresses.append(cur_addr)
            original_halfwords.append(orig)
            patched_halfwords.append(int(patched) & 0xFFFF)
    except Exception:
        return {
            "supported": False,
            "reason": "instruction_patch_out_of_range",
            "model": model,
            "original_halfwords": original_halfwords,
            "patched_halfwords": patched_halfwords,
            "patched_addresses": patched_addresses,
            "instruction_count": count,
        }

    return {
        "supported": True,
        "reason": None,
        "model": model,
        "original_halfwords": original_halfwords,
        "patched_halfwords": patched_halfwords,
        "patched_addresses": patched_addresses,
        "instruction_count": count,
    }


@lru_cache(maxsize=None)
def _load_elf_segments(elf_path):
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

    segments = []
    with open(elf_path, "rb") as handle:
        elf = ELFFile(handle)
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD" and seg.header.p_filesz > 0:
                vaddr = int(seg.header.p_vaddr)
                data = seg.data()
                segments.append((vaddr, vaddr + len(data), data))
    return tuple(segments)


def make_elf_halfword_reader(elf_path):
    """Return a callable that reads little-endian Thumb halfwords from *elf_path*."""
    segments = _load_elf_segments(str(elf_path))

    def read_halfword(addr):
        target = int(addr)
        for seg_start, seg_end, seg_data in segments:
            if target < seg_start or target + 2 > seg_end:
                continue
            offset = target - seg_start
            return int.from_bytes(seg_data[offset : offset + 2], "little")
        raise KeyError("address 0x{:X} not present in ELF load segments".format(target))

    return read_halfword
