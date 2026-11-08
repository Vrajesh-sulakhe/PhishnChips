"""
re_engine.py - Autonomous Static Reverse Engineering & Disassembly Engine.
Performs zero-execution static inspection of dropped PE/ELF binaries and WebAssembly (.wasm) modules,
extracting section entropy, suspicious API capabilities, imported JS host bindings, and embedded C2 IOCs.
"""

import math
import struct
import collections
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte buffer (0.0 = uniform, 8.0 = maximum randomness/encryption)."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


class PEInspector:
    """Zero-execution static inspector for Windows Portable Executable (PE32 / PE32+) binaries."""

    SUSPICIOUS_API_PATTERNS = {
        "Process Injection / Code Modification": [
            b"VirtualAllocEx", b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread",
            b"NtMapViewOfSection", b"QueueUserAPC", b"RtlMoveMemory", b"VirtualProtect"
        ],
        "Credential Access / DPAPI Theft": [
            b"CryptUnprotectData", b"CredEnumerate", b"CredRead", b"LsaRetrievePrivateData",
            b"SamEnumerateUsersInDomain", b"VaultGetItem", b"CryptDecrypt"
        ],
        "Anti-Analysis & Sandbox Evasion": [
            b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess",
            b"GetTickCount", b"QueryPerformanceCounter", b"GetSystemInfo", b"OutputDebugString"
        ],
        "Network C2 Communication & Downloaders": [
            b"InternetOpenW", b"InternetOpenA", b"HttpSendRequestW", b"HttpSendRequestA",
            b"InternetConnectW", b"InternetConnectA", b"URLDownloadToFileW", b"URLDownloadToFileA",
            b"WSAStartup", b"connect", b"send", b"WSASocketW"
        ],
        "Keystroke Logging & Input Sniffing": [
            b"SetWindowsHookExW", b"SetWindowsHookExA", b"GetAsyncKeyState", b"GetKeyState",
            b"GetKeyboardState", b"RegisterHotKey"
        ]
    }

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = file_path.read_bytes() if file_path.exists() else b""

    def analyze(self) -> Dict[str, Any]:
        if len(self.data) < 64 or self.data[:2] != b"MZ":
            return {
                "is_valid_pe": False,
                "error": "Not a valid PE binary (missing MZ DOS signature)"
            }

        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if e_lfanew + 24 > len(self.data) or self.data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return {
                "is_valid_pe": False,
                "error": "Invalid PE header signature"
            }

        # Parse COFF File Header (20 bytes after PE\0\0)
        coff_offset = e_lfanew + 4
        machine, num_sections, timestamp, _, _, size_of_opt_header, characteristics = struct.unpack_from(
            "<HHIIIHH", self.data, coff_offset
        )

        arch_map = {
            0x014C: "x86",
            0x8664: "x86_64",
            0x0200: "ia64",
            0xAA64: "arm64"
        }
        architecture = arch_map.get(machine, f"Unknown ({hex(machine)})")

        # Parse Optional Header
        opt_offset = coff_offset + 20
        opt_magic = struct.unpack_from("<H", self.data, opt_offset)[0] if opt_offset + 2 <= len(self.data) else 0
        pe_format = "PE32+ (64-bit)" if opt_magic == 0x020B else ("PE32 (32-bit)" if opt_magic == 0x010B else "Unknown")

        # Parse Section Headers
        sections_offset = opt_offset + size_of_opt_header
        sections = []
        high_entropy_sections = []

        for i in range(num_sections):
            sec_header_offset = sections_offset + (i * 40)
            if sec_header_offset + 40 > len(self.data):
                break
            raw_name = self.data[sec_header_offset:sec_header_offset + 8].rstrip(b"\x00")
            name = raw_name.decode("utf-8", errors="replace")

            virt_size, virt_addr, raw_size, raw_offset = struct.unpack_from(
                "<IIII", self.data, sec_header_offset + 8
            )

            # Extract raw section bytes and compute entropy
            sec_bytes = b""
            if raw_offset + raw_size <= len(self.data) and raw_size > 0:
                sec_bytes = self.data[raw_offset:raw_offset + raw_size]
            elif raw_offset < len(self.data):
                sec_bytes = self.data[raw_offset:]

            entropy = round(calculate_entropy(sec_bytes), 2)
            is_packed = entropy > 7.2

            sec_info = {
                "name": name,
                "virtual_size": virt_size,
                "virtual_address": hex(virt_addr),
                "raw_size": raw_size,
                "entropy": entropy,
                "is_packed": is_packed
            }
            sections.append(sec_info)
            if is_packed:
                high_entropy_sections.append(name)

        # Detect suspicious API capabilities from byte content / IAT
        detected_capabilities = []
        detected_apis = []
        for category, api_list in self.SUSPICIOUS_API_PATTERNS.items():
            matched_apis = [api.decode("ascii") for api in api_list if api in self.data]
            if matched_apis:
                detected_capabilities.append(category)
                detected_apis.extend(matched_apis)

        # Extract embedded IOC strings
        extracted_iocs = self._extract_iocs()

        overall_entropy = round(calculate_entropy(self.data), 2)
        is_suspicious = (
            len(high_entropy_sections) > 0 or
            len(detected_capabilities) >= 2 or
            len(extracted_iocs["telegram_tokens"]) > 0
        )

        return {
            "is_valid_pe": True,
            "filename": self.file_path.name,
            "size_bytes": len(self.data),
            "architecture": architecture,
            "pe_format": pe_format,
            "timestamp": timestamp,
            "overall_entropy": overall_entropy,
            "sections_count": len(sections),
            "sections": sections,
            "high_entropy_sections": high_entropy_sections,
            "is_packed": len(high_entropy_sections) > 0 or overall_entropy > 7.3,
            "detected_capabilities": detected_capabilities,
            "matched_apis": detected_apis[:15],
            "extracted_iocs": extracted_iocs,
            "is_suspicious": is_suspicious
        }

    def _extract_iocs(self) -> Dict[str, List[str]]:
        """Scans binary content for common malicious IOC patterns."""
        text = self.data.decode("latin-1", errors="ignore")

        # IPv4 pattern (excluding localhost / zeroes)
        ipv4_matches = set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text))
        clean_ips = [
            ip for ip in ipv4_matches
            if not ip.startswith(("127.", "0.", "255.", "192.168.", "10."))
        ][:8]

        # URLs
        url_matches = set(re.findall(r"https?://[a-zA-Z0-9_\-\.\:]+/[a-zA-Z0-9_\-\.\/\?\=\&\%\#]*", text))
        clean_urls = list(url_matches)[:8]

        # Telegram Bot tokens
        telegram_tokens = list(set(re.findall(r"bot\d{8,12}:[A-Za-z0-9_-]{10,}", text)))

        return {
            "ipv4": clean_ips,
            "urls": clean_urls,
            "telegram_tokens": telegram_tokens
        }


class WasmInspector:
    """Zero-execution static inspector for WebAssembly (.wasm) evasion modules."""

    SECTION_NAMES = {
        0: "Custom",
        1: "Type",
        2: "Import",
        3: "Function",
        4: "Table",
        5: "Memory",
        6: "Global",
        7: "Export",
        8: "Start",
        9: "Element",
        10: "Code",
        11: "Data",
        12: "DataCount"
    }

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data = file_path.read_bytes() if file_path.exists() else b""

    def analyze(self) -> Dict[str, Any]:
        if len(self.data) < 8 or self.data[:4] != b"\x00asm":
            return {
                "is_valid_wasm": False,
                "error": "Not a valid WebAssembly binary (missing \\0asm magic)"
            }

        version = struct.unpack_from("<I", self.data, 4)[0]

        offset = 8
        sections: List[Dict[str, Any]] = []
        imports: List[str] = []
        exports: List[str] = []
        data_strings: List[str] = []

        while offset < len(self.data):
            sec_id = self.data[offset]
            offset += 1
            sec_len, bytes_read = self._read_varuint(offset)
            offset += bytes_read

            sec_name = self.SECTION_NAMES.get(sec_id, f"Unknown ({sec_id})")
            sec_data = self.data[offset:offset + sec_len]

            sections.append({
                "id": sec_id,
                "name": sec_name,
                "size_bytes": sec_len
            })

            # Parse Import Section (id=2)
            if sec_id == 2:
                imports = self._parse_import_section(sec_data)

            # Parse Export Section (id=7)
            elif sec_id == 7:
                exports = self._parse_export_section(sec_data)

            # Parse Data Section (id=11)
            elif sec_id == 11:
                data_strings = self._extract_data_strings(sec_data)

            offset += sec_len

        # Evasion & Behavior Analysis
        evasion_flags = {
            "dynamic_eval": any("eval" in imp.lower() or "function" in imp.lower() for imp in imports),
            "dom_manipulation": any("document" in imp.lower() or "window" in imp.lower() or "cookie" in imp.lower() for imp in imports),
            "network_beacon": any("fetch" in imp.lower() or "http" in imp.lower() or "xml" in imp.lower() for imp in imports) or any("http" in s for s in data_strings),
            "credential_scraper": any("password" in exp.lower() or "decrypt" in exp.lower() or "phish" in exp.lower() for exp in exports)
        }

        # Generate pseudo-WAT summary
        wat_lines = [f";; WebAssembly Module: {self.file_path.name} (version {version})"]
        for imp in imports:
            wat_lines.append(f'(import "{imp.split(".")[0]}" "{imp.split(".")[1] if "." in imp else imp}" (func))')
        for exp in exports:
            wat_lines.append(f'(export "{exp}" (func ${exp}))')
        if not wat_lines[1:]:
            wat_lines.append(";; No explicit string imports or exports extracted")
        pseudo_wat = "\n".join(wat_lines)

        return {
            "is_valid_wasm": True,
            "filename": self.file_path.name,
            "size_bytes": len(self.data),
            "version": version,
            "sections": sections,
            "imports": imports,
            "exports": exports,
            "data_strings": data_strings[:10],
            "evasion_flags": evasion_flags,
            "pseudo_wat": pseudo_wat,
            "is_evasive": any(evasion_flags.values())
        }

    def _read_varuint(self, offset: int) -> Tuple[int, int]:
        """Decodes variable-length LEB128 unsigned integer."""
        result = 0
        shift = 0
        bytes_read = 0
        while offset + bytes_read < len(self.data):
            byte = self.data[offset + bytes_read]
            bytes_read += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, bytes_read

    def _parse_import_section(self, sec_data: bytes) -> List[str]:
        """Extracts imported module and field identifiers from import section."""
        imports = []
        try:
            pos = 0
            count = sec_data[pos]
            pos += 1
            for _ in range(min(count, 50)):
                if pos >= len(sec_data):
                    break
                mod_len = sec_data[pos]
                pos += 1
                mod_name = sec_data[pos:pos + mod_len].decode("utf-8", errors="replace")
                pos += mod_len

                field_len = sec_data[pos]
                pos += 1
                field_name = sec_data[pos:pos + field_len].decode("utf-8", errors="replace")
                pos += field_len

                # Skip kind (1 byte) + type/desc
                pos += 2
                imports.append(f"{mod_name}.{field_name}")
        except Exception:
            pass
        return imports

    def _parse_export_section(self, sec_data: bytes) -> List[str]:
        """Extracts exported entrypoint names from export section."""
        exports = []
        try:
            pos = 0
            count = sec_data[pos]
            pos += 1
            for _ in range(min(count, 50)):
                if pos >= len(sec_data):
                    break
                exp_len = sec_data[pos]
                pos += 1
                exp_name = sec_data[pos:pos + exp_len].decode("utf-8", errors="replace")
                pos += exp_len

                # Skip kind + index
                pos += 2
                exports.append(exp_name)
        except Exception:
            pass
        return exports

    def _extract_data_strings(self, sec_data: bytes) -> List[str]:
        """Extracts ASCII / UTF-8 strings embedded inside data segments."""
        matches = re.findall(rb"[a-zA-Z0-9_\-\.\:\/\?\=\&\@]{8,}", sec_data)
        return [m.decode("utf-8", errors="ignore") for m in matches][:10]


def analyze_quarantined_artifacts(job_dir: Path) -> Dict[str, Any]:
    """
    Scans a job's evidence folder for quarantined binaries and WebAssembly modules,
    performing comprehensive static reverse engineering without executing anything.
    """
    payloads_dir = job_dir / "payloads"
    wasm_dir = job_dir / "wasm"

    binaries_report = []
    wasm_report = []

    if payloads_dir.exists() and payloads_dir.is_dir():
        for f in payloads_dir.iterdir():
            if f.is_file():
                inspector = PEInspector(f)
                binaries_report.append(inspector.analyze())

    if wasm_dir.exists() and wasm_dir.is_dir():
        for f in wasm_dir.iterdir():
            if f.is_file():
                inspector = WasmInspector(f)
                wasm_report.append(inspector.analyze())

    has_artifacts = len(binaries_report) > 0 or len(wasm_report) > 0

    risk_level = "LOW"
    if any(b.get("is_suspicious") for b in binaries_report) or any(w.get("is_evasive") for w in wasm_report):
        risk_level = "CRITICAL"
    elif has_artifacts:
        risk_level = "HIGH"

    summary_parts = []
    if binaries_report:
        summary_parts.append(f"{len(binaries_report)} binary payload(s) dissected statically")
    if wasm_report:
        summary_parts.append(f"{len(wasm_report)} WebAssembly evasion module(s) analyzed")
    summary = ", ".join(summary_parts) if summary_parts else "No dropped binaries or WebAssembly modules detected."

    return {
        "has_quarantined_artifacts": has_artifacts,
        "total_binaries": len(binaries_report),
        "total_wasm_modules": len(wasm_report),
        "binaries": binaries_report,
        "wasm_modules": wasm_report,
        "risk_level": risk_level,
        "summary": summary
    }
