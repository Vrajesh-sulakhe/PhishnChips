import math
import struct
import pytest
from pathlib import Path

from re_engine import (
    calculate_entropy,
    PEInspector,
    WasmInspector,
    analyze_quarantined_artifacts,
)


def create_minimal_pe() -> bytes:
    """Constructs a valid minimal PE32 structure in bytes for testing."""
    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)  # e_lfanew = 64

    # PE Signature (4 bytes)
    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    # Machine = 0x8664 (x86_64), NumberOfSections = 2, TimeDateStamp = 1600000000
    # PointerToSymbolTable = 0, NumberOfSymbols = 0, SizeOfOptionalHeader = 240, Characteristics = 0x0022
    coff_header = struct.pack("<HHIIIHH", 0x8664, 2, 1600000000, 0, 0, 240, 0x0022)

    # Optional Header (PE32+ 64-bit, 240 bytes)
    opt_header = bytearray(240)
    struct.pack_into("<H", opt_header, 0, 0x020B)  # Magic = PE32+ (64-bit)
    struct.pack_into("<Q", opt_header, 24, 0x00400000)  # ImageBase
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint

    # Data Directories (Import Table at offset 120 of Optional Header)
    # VirtualAddress = 0x3000, Size = 100
    struct.pack_into("<II", opt_header, 120, 0x3000, 100)

    # Section Headers (40 bytes each)
    # Section 1: .text (VirtualSize = 0x1000, VirtualAddress = 0x1000, SizeOfRawData = 512, PointerToRawData = 512)
    sec1 = bytearray(40)
    sec1[0:5] = b".text"
    struct.pack_into("<IIII", sec1, 8, 0x1000, 0x1000, 512, 512)

    # Section 2: .rdata (VirtualSize = 0x1000, VirtualAddress = 0x2000, SizeOfRawData = 512, PointerToRawData = 1024)
    sec2 = bytearray(40)
    sec2[0:6] = b".rdata"
    struct.pack_into("<IIII", sec2, 8, 0x1000, 0x2000, 512, 1024)

    pe_data = bytearray()
    pe_data.extend(dos_header)
    pe_data.extend(pe_sig)
    pe_data.extend(coff_header)
    pe_data.extend(opt_header)
    pe_data.extend(sec1)
    pe_data.extend(sec2)

    # Pad to raw data offset (512)
    if len(pe_data) < 512:
        pe_data.extend(b"\x00" * (512 - len(pe_data)))

    # .text raw data with embedded suspicious string
    text_content = b"Starting dropper... Contacting C2 at http://185.220.101.5:8080/gate and bot7182940182:AAFakeToken"
    text_content = text_content + b"\x90" * (512 - len(text_content))
    pe_data.extend(text_content)

    # .rdata with API names
    rdata_content = b"VirtualAllocEx\x00WriteProcessMemory\x00CryptUnprotectData\x00InternetOpenW\x00"
    rdata_content = rdata_content + b"\x00" * (512 - len(rdata_content))
    pe_data.extend(rdata_content)

    return bytes(pe_data)


def create_minimal_wasm() -> bytes:
    """Constructs a valid minimal WebAssembly module in bytes."""
    # WASM binary magic (\0asm) + version 1
    wasm_magic = b"\x00asm\x01\x00\x00\x00"

    # Section 1: Type Section (id=1, payload length=7)
    # 1 type: func () -> ()
    type_section = b"\x01\x07\x01\x60\x02\x7f\x7f\x01\x7f"

    # Section 2: Import Section (id=2)
    # 1 import: module="env", field="eval_js", kind=0 (func), type_idx=0
    import_payload = b"\x01\x03env\x07eval_js\x00\x00"
    import_section = bytes([2, len(import_payload)]) + import_payload

    # Section 7: Export Section (id=7)
    # 1 export: name="decrypt_phish_payload", kind=0, func_idx=1
    export_name = b"decrypt_phish_payload"
    export_payload = bytes([1, len(export_name)]) + export_name + b"\x00\x01"
    export_section = bytes([7, len(export_payload)]) + export_payload

    # Section 11: Data Section (id=11)
    # 1 data segment with string
    data_str = b"https://evil-exfiltrator-test.com/wasm_beacon"
    data_payload = bytes([1, 0, 0x41, 0, 0x0B, len(data_str)]) + data_str
    data_section = bytes([11, len(data_payload)]) + data_payload

    return wasm_magic + type_section + import_section + export_section + data_section


def test_calculate_entropy():
    # Empty bytes
    assert calculate_entropy(b"") == 0.0

    # Constant bytes (zero entropy)
    assert calculate_entropy(b"A" * 100) == 0.0

    # High entropy (random / compressed)
    random_data = bytes([i % 256 for i in range(1000)])
    ent = calculate_entropy(random_data)
    assert 7.0 < ent <= 8.0


def test_pe_inspector_analysis(tmp_path):
    pe_bytes = create_minimal_pe()
    file_path = tmp_path / "test_dropper.exe"
    file_path.write_bytes(pe_bytes)

    inspector = PEInspector(file_path)
    res = inspector.analyze()

    assert res["is_valid_pe"] is True
    assert res["architecture"] == "x86_64"
    assert res["sections_count"] == 2
    assert len(res["sections"]) == 2
    assert res["sections"][0]["name"] == ".text"
    assert res["sections"][1]["name"] == ".rdata"

    # Verify detected suspicious capabilities
    caps = res["detected_capabilities"]
    assert any("injection" in c.lower() or "virtualalloc" in c.lower() for c in caps)
    assert any("credential" in c.lower() or "crypt" in c.lower() for c in caps)

    # Verify IOC extraction
    iocs = res["extracted_iocs"]
    assert "185.220.101.5" in iocs["ipv4"] or any("185.220.101.5" in u for u in iocs["urls"])
    assert any("7182940182" in t for t in iocs["telegram_tokens"])


def test_wasm_inspector_analysis(tmp_path):
    wasm_bytes = create_minimal_wasm()
    file_path = tmp_path / "stealth.wasm"
    file_path.write_bytes(wasm_bytes)

    inspector = WasmInspector(file_path)
    res = inspector.analyze()

    assert res["is_valid_wasm"] is True
    assert res["version"] == 1
    assert "env.eval_js" in res["imports"] or any("eval_js" in imp for imp in res["imports"])
    assert "decrypt_phish_payload" in res["exports"]
    assert any("evil-exfiltrator-test.com" in s for s in res["data_strings"])
    assert res["evasion_flags"]["dynamic_eval"] is True


def test_analyze_quarantined_artifacts(tmp_path):
    job_dir = tmp_path / "test_job_123"
    payloads_dir = job_dir / "payloads"
    wasm_dir = job_dir / "wasm"
    payloads_dir.mkdir(parents=True)
    wasm_dir.mkdir(parents=True)

    # Place a PE and a WASM file
    (payloads_dir / "update.exe").write_bytes(create_minimal_pe())
    (wasm_dir / "module.wasm").write_bytes(create_minimal_wasm())

    summary = analyze_quarantined_artifacts(job_dir)
    assert summary["has_quarantined_artifacts"] is True
    assert summary["total_binaries"] == 1
    assert summary["total_wasm_modules"] == 1
    assert len(summary["binaries"]) == 1
    assert len(summary["wasm_modules"]) == 1
    assert summary["risk_level"] in ("HIGH", "CRITICAL")

