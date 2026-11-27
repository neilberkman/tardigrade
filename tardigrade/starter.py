"""Derive a single-image upgrade from a loader's compiled memory map."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import shutil
import struct
import tempfile
import zlib

from devicetree import dtlib
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
import yaml

from profile_loader import (MCUBOOT_ALIGNED_MAGIC_SUFFIX, MCUBOOT_GOOD_MAGIC,
                            ProfileError, load_profile, mcuboot_validated_image_extent)

from .cli import RUNTIME


@dataclass(frozen=True)
class Image:
    family: str
    prefix: int
    header: int
    size: int
    extent: int
    stack: int
    reset: int
    version_word: int
    platform_id: int | None


@dataclass(frozen=True)
class Layout:
    platform: str
    sram: tuple[int, int]
    slots: dict[str, dict[str, int]]
    write_size: int
    mode: str
    trigger: dict | None = None
    staging_offset: int = 0


def inspect_image(raw):
    prefix = len(raw) - len(raw.lstrip(b"\xff"))
    data = raw[prefix:]
    if len(data) < 32:
        raise ValueError("truncated image header")
    if data[:4] == b"NXOS":
        header, checksum, size = struct.unpack_from("<HII", data, 6)
        extent = header + size
        if (header < 34 or data[4:6] != b"\x01\x00" or prefix or extent > len(data)
                or zlib.crc32(data[12:extent]) != checksum):
            raise ValueError("invalid nxboot header, length or CRC")
        family, version_at = "nxboot", 28
    elif data[:4] == struct.pack("<I", 0x96F3B83D):
        header, _, size, flags = struct.unpack_from("<HHII", data, 8)
        extent = mcuboot_validated_image_extent(data)
        if not extent or extent > len(data) or flags or int.from_bytes(data[4:8], "little"):
            raise ValueError("expected a complete, uncompressed flash-resident MCUboot image with TLVs")
        family, version_at = "mcuboot", 20
    else:
        raise ValueError("unrecognized image header (expected MCUboot or nxboot)")
    if header % 4 or size < 8 or header + 8 > len(data):
        raise ValueError("invalid vector table offset or payload length")
    stack, reset = struct.unpack_from("<II", data, header)
    return Image(family, prefix, header, size, extent, stack, reset,
                 struct.unpack_from("<I", data, version_at)[0],
                 struct.unpack_from("<Q", data, 16)[0] if family == "nxboot" else None)


def symbol_bytes(elf, symbol):
    section = elf.get_section(symbol["st_shndx"])
    offset = symbol["st_value"] - section["sh_addr"]
    end = offset + symbol["st_size"]
    if offset < 0 or end > section["sh_size"]:
        raise ValueError(f"invalid bounds for ELF symbol {symbol.name}")
    return section.data()[offset:end]


def loader_info(path):
    try:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf["e_machine"] != "EM_ARM" or not elf.little_endian or elf.elfclass != 32:
                raise ValueError("a 32-bit little-endian Cortex-M loader ELF is required")
            loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD" and s["p_filesz"]]
            first = min(loads, key=lambda s: s["p_paddr"])
            entry = first["p_paddr"]
            if first["p_filesz"] < 8:
                raise ValueError("bootloader vector table is truncated")
            stack, reset = struct.unpack_from("<II", first.data())
            if not reset & 1 or not any(s["p_vaddr"] <= reset - 1 < s["p_vaddr"] + s["p_filesz"]
                                        for s in loads if s["p_flags"] & 1):
                raise ValueError("ELF reset vector does not point into executable code")
            tab = elf.get_section_by_name(".symtab")
            symbols = {s.name: s for s in tab.iter_symbols()} if tab else {}
            tables = {name: symbol_bytes(elf, symbols[name]) for name in
                      ("default_flash_map", "boot_img_magic", "g_ota_partition_table") if name in symbols}
            if "g_ota_partition_table" in tables:
                partitions = {}
                for offset, size, address in struct.iter_unpack("<III", tables["g_ota_partition_table"]):
                    segment = next((s for s in loads if s["p_vaddr"] <= address < s["p_vaddr"] + s["p_filesz"]), None)
                    require(segment is not None, "NuttX partition device path is outside the ELF")
                    start = address - segment["p_vaddr"]
                    name, terminator, _ = segment.data()[start:start + 64].partition(b"\0")
                    require(terminator and name.startswith(b"/dev/"), "invalid partition device path in ELF")
                    device = name.decode("ascii")
                    require(device not in partitions, "duplicate partition device in ELF")
                    partitions[device] = (offset, size)
                tables["nxboot_partitions"] = partitions
            slot_lists = {symbol_bytes(elf, s) for s in (tab.iter_symbols() if tab else ())
                          if s.name.startswith("all_slots.") and s["st_size"] == 8}
            if len(slot_lists) == 1:
                tables["slot_ids"] = slot_lists.pop()
            return entry, stack, set(symbols), tables
    except (ELFError, struct.error) as exc:
        raise ValueError(f"invalid bootloader ELF {path}: {exc}") from exc


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reg(node):
    cells = node.props["reg"].to_nums()
    require(len(cells) == 2, f"{node.path} must have one 32-bit address and size")
    return tuple(cells)


def one_node(nodes, description):
    require(len(nodes) == 1, f"expected one {description}, found {len(nodes)}")
    return nodes[0]


def zephyr_layout(directory, cfg, entry, symbols, tables, primary, update):
    try:
        tree = dtlib.DT(str(directory / "zephyr.dts"))
        chosen = tree.get_node("/chosen")
        flash = chosen.props["zephyr,flash"].to_path()
        sram = reg(chosen.props["zephyr,sram"].to_path())
        flash_base, flash_size = reg(flash)
        compats = tree.get_node("/soc").props["compatible"].to_strings()
        if "nordic,nrf52840" in compats and cfg.get("CONFIG_SOC_NRF52840") == "y":
            platform, family_symbol = "cortex_m4_flash_fast", "nordicsemi_nrf52_init"
            expected_flash = 0
        elif "st,stm32f429" in compats and cfg.get("CONFIG_SOC_STM32F429XX") == "y":
            platform, family_symbol = "stm32f4_fast", "st_stm32f4_init"
            expected_flash = 0x08000000
        else:
            raise ValueError("cannot match a supported SoC in both devicetree and .config")
        require(flash_base == expected_flash and int(cfg["CONFIG_FLASH_BASE_ADDRESS"], 0) == flash_base,
                "flash base disagrees with platform or .config")
        if {"nordicsemi_nrf52_init", "st_stm32f4_init"} & symbols:
            require(family_symbol in symbols, "ELF SoC conflicts with devicetree")
        partitions = one_node([n for n in flash.nodes.values() if "compatible" in n.props
                               and "fixed-partitions" in n.props["compatible"].to_strings()],
                              "fixed-partitions table on the chosen flash")
        slots = {}
        for name, label in (("exec", "image-0"), ("staging", "image-1")):
            part = one_node([n for n in partitions.nodes.values() if n.props.get("label")
                             and n.props["label"].to_string() == label], f"partition labelled {label}")
            off, size = reg(part)
            require(0 < size <= flash_size - off, f"{part.path} exceeds chosen flash")
            slots[name] = {"base": flash_base + off, "size": size}
        boot_node = chosen.props["zephyr,code-partition"].to_path()
        require(boot_node.parent is partitions and flash_base + reg(boot_node)[0] == entry,
                "ELF vector table differs from the chosen bootloader partition")
        modes = [mode for mode in ("move", "scratch", "offset")
                 if cfg.get(f"CONFIG_BOOT_SWAP_USING_{mode.upper()}") == "y"]
        require(len(modes) == 1 and cfg.get("CONFIG_BOOT_UPGRADE_ONLY") != "y"
                and cfg.get("CONFIG_UPDATEABLE_IMAGE_NUMBER", "1") == "1",
                "need exactly one supported single-image MCUboot swap mode in bootloader .config")
        mode = modes[0]
        if mode == "scratch":
            scratch = one_node([n for n in partitions.nodes.values() if n.props.get("label")
                                and n.props["label"].to_string() == "image-scratch"], "scratch partition")
            off, size = reg(scratch)
            slots["scratch"] = {"base": flash_base + off, "size": size}
        if "default_flash_map" in tables:
            entries = list(struct.iter_unpack("<IIII", tables["default_flash_map"]))
            ids = dict(zip(("exec", "staging"), struct.unpack("<II", tables["slot_ids"]))) if "slot_ids" in tables else {}
            devices = set()
            for name, slot in slots.items():
                hits = [e for e in entries if e[1:3] == (slot["base"] - flash_base, slot["size"])
                        and (name not in ids or e[0] == ids[name])]
                require(len(hits) == 1, f"{name} partition disagrees with compiled ELF flash map")
                devices.add(hits[0][3])
            require(len(devices) == 1, "image partitions refer to different flash devices")
        write_size = flash.props["write-block-size"].to_num()
        magic = tables.get("boot_img_magic")
        if magic == struct.pack("<4I", *MCUBOOT_GOOD_MAGIC):
            align = 8
        elif magic and magic[2:] == MCUBOOT_ALIGNED_MAGIC_SUFFIX:
            align = int.from_bytes(magic[:2], "little")
        elif magic is None:
            align = int(cfg["CONFIG_BOOT_MAX_ALIGN"], 0)
        else:
            raise ValueError("unrecognized compiled MCUboot trailer magic")
        if "CONFIG_BOOT_MAX_ALIGN" in cfg:
            require(align == int(cfg["CONFIG_BOOT_MAX_ALIGN"], 0), "trailer alignment disagrees with .config")
        require(align >= 1 and align & (align - 1) == 0, "invalid MCUboot trailer alignment")
        sector = 0
        if mode == "offset":
            base = slots["staging"]["base"] - flash_base
            if platform == "stm32f4_fast":
                bank_off = base % 0x100000
                sector = 0x4000 if bank_off < 0x10000 else 0x10000 if bank_off < 0x20000 else 0x20000
            else:
                sector = flash.props["erase-block-size"].to_num()
            require(0 < sector < slots["staging"]["size"] and base % sector == 0, "invalid staging erase geometry")
            require(update.prefix in (0, sector), "staging header must follow exactly one erased sector for offset swap")
        else:
            require(update.prefix == 0, f"{mode} swap requires the update header at the staging base")
        require(primary.prefix == 0, "primary slot must begin with its image header")
        trigger = {"type": "mcuboot_trailer_magic", "slot": "staging", "max_align": align}
        return Layout(platform, sram, slots, write_size, mode, trigger, sector)
    except (KeyError, dtlib.DTError, struct.error) as exc:
        raise ValueError(f"incomplete Zephyr build metadata: {exc}") from exc


# These exact build products were produced by scripts/build_mcuboot_head_matrix.sh.
# Swap selection is a build option. Neither the filename nor the Cortex-M ISA
# identifies it. Read partition addresses and slot IDs from the actual binary.
TRACKED_MOVE_BUILDS = {
    "eb1697ba4db5cb3916e5a568f145e5c590a7a8a4fbd0cfafb8a8c68638a3e554": ("cortex_m4_flash_fast", 0x40000, 4),
    "0e95b2e3606a44a9a6d900172d5c97d11e2d814ef87c4b7604c5b1894f298dcb": ("stm32f4_fast", 0x30000, 1),
}


def tracked_layout(path, entry, tables, primary, update):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    require(digest in TRACKED_MOVE_BUILDS,
            "cannot establish board, named partitions and swap mode without the bootloader build metadata")
    board, ram_size, granularity = TRACKED_MOVE_BUILDS[digest]
    slot_ids = struct.unpack("<II", tables["slot_ids"])
    areas = {i: (off, size) for i, off, size, _ in struct.iter_unpack("<IIII", tables["default_flash_map"])}
    slots = {}
    for name, i in zip(("exec", "staging"), slot_ids):
        offset, size = areas[i]
        slots[name] = {"base": entry + offset, "size": size}
    require(primary.prefix == update.prefix == 0, "move swap requires unpadded image headers")
    require(tables["boot_img_magic"] == struct.pack("<4I", *MCUBOOT_GOOD_MAGIC), "unexpected trailer magic")
    trigger = {"type": "mcuboot_trailer_magic", "slot": "staging", "max_align": 8}
    return Layout(board, (0x20000000, ram_size), slots, granularity, "move", trigger)


def nuttx_layout(cfg, entry, tables, primary, update):
    require(cfg.get("CONFIG_ARCH_BOARD_NUCLEO_H743ZI") == "y" and cfg.get("CONFIG_NXBOOT_BOOTLOADER") == "y"
            and cfg.get("CONFIG_ARCH_CHIP_STM32H743ZI") == "y", "need a nucleo-h743zi nxboot loader .config")
    require(entry == 0x08000000, "ELF is outside the board boot flash")
    slots = {}
    try:
        partitions = tables["nxboot_partitions"]
        require(len(partitions) == 3, "expected three compiled NuttX OTA partitions")
        for role, name in zip(("PRIMARY", "SECONDARY", "TERTIARY"), ("exec", "staging", "tertiary")):
            device = cfg[f"CONFIG_NXBOOT_{role}_SLOT_PATH"].strip('"')
            offset, size = partitions[device]
            require(offset == int(cfg[f"CONFIG_STM32_OTA_{role}_SLOT_OFFSET"], 0)
                    and size == int(cfg["CONFIG_STM32_OTA_SLOT_SIZE"], 0)
                    and device == cfg[f"CONFIG_STM32_OTA_{role}_SLOT_DEVPATH"].strip('"'),
                    f"{role} slot in ELF or loader device mapping disagrees with .config")
            require(0 < size <= 0x200000 - offset, f"{role} slot exceeds board flash")
            slots[name] = {"base": entry + offset, "size": size}
        require(primary.platform_id == update.platform_id == int(cfg["CONFIG_NXBOOT_PLATFORM_IDENTIFIER"], 0),
                "nxboot platform ID disagrees with loader .config")
        require(primary.header == update.header == int(cfg["CONFIG_NXBOOT_HEADER_SIZE"], 0),
                "nxboot header offset disagrees with loader .config")
    except (KeyError, struct.error) as exc:
        raise ValueError(f"missing NuttX partition evidence: {exc}") from exc
    return Layout("nucleo_h753zi_tardigrade", (0x24000000, 0x80000), slots, 8, "nxboot")


def generate(args):
    output = args.output.resolve()
    require(not output.exists(), f"output already exists: {output}")
    paths = [p.resolve(strict=True) for p in (args.bootloader, args.primary, args.update)]
    entry, stack, symbols, tables = loader_info(paths[0])
    blobs = [p.read_bytes() for p in paths[1:]]
    primary, update = map(inspect_image, blobs)
    require(primary.family == update.family, "image families differ")
    require(blobs[0][primary.prefix:primary.prefix + primary.extent] !=
            blobs[1][update.prefix:update.prefix + update.extent], "update is identical to the primary image")
    if primary.family == "nxboot":
        require(primary.platform_id == update.platform_id, "nxboot platform IDs differ")
    directory = (args.build_dir or paths[0].parent).resolve()
    if (directory / "zephyr/.config").is_file():
        directory = directory / "zephyr"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        work = Path(tmp)
        assets = output.with_suffix(".inputs")
        require(assets != output, "choose a YAML output name")
        names = []
        for role, source in zip(("loader", "primary", "update"), paths):
            if source.is_relative_to(output.parent):
                name = source.relative_to(output.parent)
            else:
                require(not assets.exists(), f"input directory already exists: {assets}")
                name = Path(assets.name) / (role + source.suffix)
                (work / name.parent).mkdir(exist_ok=True)
                shutil.copyfile(source, work / name)
            names.append(str(name))
        profile = {
            "schema_version": 1, "name": f"{primary.family}_starter", "platform": "UNRESOLVED",
            "flash_backend": "UNRESOLVED",
            "bootloader": {"elf": names[0], "entry": entry},
            "memory": {"sram": "UNRESOLVED", "write_granularity": "UNRESOLVED", "slots": "UNRESOLVED"},
            "images": dict(zip(("exec", "staging"), names[1:])),
            "success_criteria": {"vtor_in_slot": "exec", "vector_table_offset": update.header},
            "fault_sweep": {"mode": "runtime", "evaluation_mode": "execute", "max_writes": 0,
                            "run_duration": "20.0", "max_step_limit": 1000000000, "vtor_settle_iters": 1},
            "expect": {"should_find_issues": False},
        }
        issue = None
        try:
            config_path = directory / ".config"
            if primary.family == "mcuboot" and args.build_dir is None and not config_path.exists():
                layout = tracked_layout(paths[0], entry, tables, primary, update)
            else:
                cfg = dict(line.split("=", 1) for line in config_path.read_text().splitlines()
                           if line.startswith("CONFIG_") and "=" in line)
                if primary.family == "mcuboot":
                    layout = zephyr_layout(directory, cfg, entry, symbols, tables, primary, update)
                else:
                    layout = nuttx_layout(cfg, entry, tables, primary, update)
            ram, ram_size = layout.sram
            slots = layout.slots
            require(ram < stack <= ram + ram_size, "ELF initial stack is outside target SRAM")
            ranges = sorted((v["base"], v["base"] + v["size"]) for v in slots.values())
            require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "partitions overlap")
            for name, img, blob in zip(("exec", "staging"), (primary, update), blobs):
                base = slots["exec"]["base"] + img.header
                require(len(blob) <= slots[name]["size"] and img.reset & 1
                        and base <= img.reset - 1 < base + img.size and ram < img.stack <= ram + ram_size,
                        f"{name} image length or vector table disagrees with target memory")
            if layout.staging_offset and not update.prefix:
                tail = blobs[1][update.extent:]
                require(not tail.strip(b"\xff"), "raw offset update contains trailer data; provide a prepared staging slot")
                require(layout.staging_offset + update.extent <= slots["staging"]["size"], "offset update exceeds staging slot")
                prepared = Path(assets.name) / "update-slot.bin"
                original_copy = work / names[2]
                if original_copy.is_file():
                    original_copy.unlink()
                (work / prepared.parent).mkdir(exist_ok=True)
                (work / prepared).write_bytes(b"\xff" * layout.staging_offset + blobs[1][:update.extent])
                profile["images"]["staging"] = str(prepared)
            description = "nxboot clean upgrade" if layout.mode == "nxboot" else f"MCUboot {layout.mode} clean upgrade"
            profile.update(platform=f"platforms/{layout.platform}.repl", flash_backend="faultFlash", description=description)
            profile["memory"] = {"sram": {"start": ram, "end": ram + ram_size},
                                 "write_granularity": layout.write_size, "slots": slots}
            if layout.trigger:
                profile["update_trigger"] = layout.trigger
            if primary.family == "mcuboot" and not layout.staging_offset:
                profile["success_criteria"].update(image_hash=True, expected_image="staging")
            else:
                marker = 28 if primary.family == "nxboot" else 20
                require(update.version_word != primary.version_word, "image version marker does not distinguish the update")
                profile["success_criteria"].update(marker_address=slots["exec"]["base"] + marker,
                                                   marker_value=update.version_word)
        except (ValueError, OSError) as exc:
            issue = str(exc)
            if primary.family == "mcuboot":
                profile.setdefault("update_trigger", "UNRESOLVED")
            profile["description"] = f"UNRESOLVED target layout or update configuration: {issue}"
        staged = work / output.name
        if issue:
            profile["unresolved"] = [issue]
        staged.write_text(yaml.safe_dump(profile, sort_keys=False))
        try:
            load_profile(staged, strict=True, repo_root=output.parent)
        except (ProfileError, ValueError, TypeError) as exc:
            if not issue:
                issue = str(exc)
                profile["unresolved"] = [issue]
                staged.write_text(yaml.safe_dump(profile, sort_keys=False))

        # Reserve the output's companion directory before publishing the YAML.
        # Neither simultaneous initializations nor a failed final link overwrite
        # an existing profile or leave it pointing to incomplete inputs.
        has_copies = (work / assets.name).is_dir()
        if has_copies:
            assets.mkdir()
        try:
            if has_copies:
                for item in (work / assets.name).iterdir():
                    item.rename(assets / item.name)
            os.link(staged, output)
        except BaseException:
            if has_copies:
                shutil.rmtree(assets)
            raise
        if issue:
            raise ValueError(f"{output} is an incomplete starter: {issue}. Supply a matching bootloader --build-dir.")
    print(f"Wrote and strictly validated {output}")
