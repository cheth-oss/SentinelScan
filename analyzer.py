
import hashlib
import re
from pathlib import Path

import pefile


# ==================================================
# FEATURE 1: FILE HASH ANALYSIS
# ==================================================

def calculate_hashes(file_path):
    """Calculate MD5 and SHA-256 fingerprints of a file."""

    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        "file_name": Path(file_path).name,
        "md5": md5_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest()
    }


# ==================================================
# FEATURE 2: STRING INSPECTION
# ==================================================

def inspect_strings(file_path):
    """Extract readable ASCII strings and basic indicators."""

    with open(file_path, "rb") as file:
        data = file.read(5 * 1024 * 1024)

    strings = re.findall(rb"[\x20-\x7E]{4,}", data)

    strings = [
        item.decode("ascii", errors="ignore")
        for item in strings
    ]

    combined_text = "\n".join(strings)

    urls = sorted(set(
        re.findall(
            r"https?://[^\s\"'<>]+",
            combined_text,
            re.IGNORECASE
        )
    ))

    ip_addresses = sorted(set(
        re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            combined_text
        )
    ))

    keywords_to_check = [
        "powershell",
        "cmd.exe",
        "rundll32",
        "virtualalloc",
        "createremotethread",
        "writeprocessmemory"
    ]

    lowercase_text = combined_text.lower()

    found_keywords = [
        word for word in keywords_to_check
        if word in lowercase_text
    ]

    return {
        "strings": strings[:200],
        "urls": urls[:100],
        "ip_addresses": ip_addresses[:100],
        "keywords": found_keywords
    }


# ==================================================
# FEATURE 3: PE FILE ANALYSIS
# ==================================================

def analyze_pe(file_path):
    """Inspect PE headers, sections, entropy and imports."""

    result = {
        "is_pe": False,
        "architecture": "Unknown",
        "machine": "Unknown",
        "number_of_sections": 0,
        "entry_point": "Unknown",
        "image_base": "Unknown",
        "sections": [],
        "imports": [],
        "error": None
    }

    pe = None

    try:
        pe = pefile.PE(str(file_path), fast_load=False)
        result["is_pe"] = True

        machine_type = pe.FILE_HEADER.Machine

        machine_names = {
            0x014c: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0x01c0: "ARM",
            0x01c4: "ARM Thumb-2",
            0xAA64: "ARM64"
        }

        result["machine"] = machine_names.get(
            machine_type,
            f"Unknown (0x{machine_type:04X})"
        )

        optional_magic = pe.OPTIONAL_HEADER.Magic

        if optional_magic == 0x10B:
            result["architecture"] = "PE32 (32-bit format)"
        elif optional_magic == 0x20B:
            result["architecture"] = "PE32+ (64-bit format)"
        else:
            result["architecture"] = "Unknown PE format"

        result["number_of_sections"] = len(pe.sections)

        result["entry_point"] = (
            f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}"
        )

        result["image_base"] = (
            f"0x{pe.OPTIONAL_HEADER.ImageBase:X}"
        )

        # Examine executable sections.
        for section in pe.sections[:50]:
            section_name = (
                section.Name.rstrip(b"\x00")
                .decode("ascii", errors="replace")
            )

            result["sections"].append({
                "name": section_name,
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "entropy": round(section.get_entropy(), 2)
            })

        # Examine imported libraries and functions.
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for imported_library in pe.DIRECTORY_ENTRY_IMPORT[:100]:
                library_name = (
                    imported_library.dll
                    .decode("ascii", errors="replace")
                )

                functions = []

                for imported_function in imported_library.imports[:200]:
                    if imported_function.name:
                        function_name = (
                            imported_function.name.decode(
                                "ascii", errors="replace"
                            )
                        )
                    else:
                        function_name = (
                            f"Ordinal {imported_function.ordinal}"
                        )

                    functions.append(function_name)

                result["imports"].append({
                    "library": library_name,
                    "functions": functions
                })

    except (pefile.PEFormatError, OSError, ValueError, OverflowError):
        result["error"] = (
            "The file could not be parsed as a valid PE executable."
        )

    finally:
        if pe is not None:
            pe.close()

    return result


# ==================================================
# FEATURE 4: MALWARE RISK ASSESSMENT ENGINE
# ==================================================

def assess_risk(inspection, pe_analysis):
    """
    Calculate a preliminary heuristic risk score from 0 to 100.

    This is an educational indicator-based score, not a malware verdict.
    """

    score = 0
    findings = []

    # Rule 1: Selected suspicious keywords.
    keywords = inspection.get("keywords", [])

    keyword_points = min(len(keywords) * 6, 30)

    if keyword_points:
        score += keyword_points
        findings.append({
            "indicator": "Suspicious keywords",
            "details": ", ".join(keywords),
            "points": keyword_points
        })

    # Rule 2: URLs found in readable strings.
    urls = inspection.get("urls", [])

    url_points = min(len(urls) * 3, 12)

    if url_points:
        score += url_points
        findings.append({
            "indicator": "URLs found",
            "details": f"{len(urls)} URL(s) found in readable strings",
            "points": url_points
        })

    # Rule 3: IPv4-looking addresses.
    ip_addresses = inspection.get("ip_addresses", [])

    ip_points = min(len(ip_addresses) * 3, 9)

    if ip_points:
        score += ip_points
        findings.append({
            "indicator": "IP-like addresses",
            "details": (
                f"{len(ip_addresses)} IPv4-looking address(es) found"
            ),
            "points": ip_points
        })

    # Rule 4: Selected APIs sometimes associated with process manipulation.
    suspicious_apis = {
        "virtualalloc",
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
        "ntunmapviewofsection",
        "setthreadcontext",
        "queueuserapc"
    }

    found_apis = []

    if pe_analysis.get("is_pe"):
        for imported_library in pe_analysis.get("imports", []):
            for function in imported_library.get("functions", []):
                if function.lower() in suspicious_apis:
                    found_apis.append(function)

    # Avoid counting the same API more than once.
    found_apis = sorted(set(found_apis))
    api_points = min(len(found_apis) * 5, 25)

    if api_points:
        score += api_points
        findings.append({
            "indicator": "Selected sensitive API imports",
            "details": ", ".join(found_apis),
            "points": api_points
        })

    # Rule 5: High-entropy PE sections.
    # High entropy can result from compression or packing.
    high_entropy_sections = []

    if pe_analysis.get("is_pe"):
        for section in pe_analysis.get("sections", []):
            try:
                entropy = float(section.get("entropy", 0))

                if entropy >= 7.2:
                    high_entropy_sections.append(
                        f"{section.get('name', 'Unknown')} "
                        f"(entropy {entropy})"
                    )
            except (TypeError, ValueError):
                continue

    entropy_points = min(len(high_entropy_sections) * 10, 20)

    if entropy_points:
        score += entropy_points
        findings.append({
            "indicator": "High-entropy PE sections",
            "details": "; ".join(high_entropy_sections),
            "points": entropy_points
        })

    # Keep the final score within 0–100.
    score = min(score, 100)

    # Assign a preliminary risk category.
    if score >= 50:
        risk_level = "High"
    elif score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not findings:
        findings.append({
            "indicator": "No configured indicators detected",
            "details": (
                "The current rules did not identify the selected indicators. "
                "This does not prove the file is safe."
            ),
            "points": 0
        })

    return {
        "score": score,
        "level": risk_level,
        "findings": findings,
        "disclaimer": (
            "This heuristic score is not a malware verdict. "
            "Legitimate software may trigger indicators, and malware "
            "may evade these checks."
        )
    }
