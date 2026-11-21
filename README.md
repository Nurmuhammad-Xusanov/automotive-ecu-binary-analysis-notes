# Automotive ECU Binary Analysis & Firmware Reverse Engineering Notes

**Author:** Nurmukhammad Khusanov  
**Focus:** Embedded Systems Security, Computer Architecture, Automotive Firmware Analysis  
**Target Architecture:** Infineon TriCore AUDO-MAX (TC1724 / TC1767 / TC1782) & Itelma M86 ECU Architecture  

---

## Abstract

Modern automotive Engine Control Units (ECUs) are safety-critical embedded systems governed by high-performance 32-bit microcontrollers. When analyzing proprietary automotive firmware dumps (`.bin`), analysts face challenges typical of bare-metal binaries: lack of symbol tables, proprietary memory segmentation, hardware-specific interrupt routing, and lack of standard executable headers (like ELF or PE).

This engineering notebook documents a structured, vendor-neutral methodology for static reverse engineering, memory mapping, and protocol analysis of automotive engine management firmware, focusing on the **Itelma M86 ECU** platform powered by **Infineon TriCore 32-bit microcontrollers**.

> **Academic & Ethical Disclaimer:** All documentation herein is compiled for educational research in embedded systems architecture, software interoperability on POSIX/Linux systems, and diagnostic protocol verification. Proprietary calibration maps, cryptographic keys, and OEM copyright binaries are explicitly excluded.

---

## 1. Hardware & Microcontroller Architecture

The Itelma M86 ECU platform commonly employs the **Infineon TriCore TC1724/TC1767** family—a unified 32-bit RISC, DSP, and microcontroller core designed specifically for powertrain management.

### Key Architectural Characteristics
- **Instruction Set Architecture (ISA):** TriCore 1.3.1 / 1.6 (Variable 16-bit and 32-bit instruction encoding).
- **Register Architecture:**
  - 16 General-Purpose Data Registers (`D0`–`D15`).
  - 16 Address Registers (`A0`–`A15`), where `A10` is the Stack Pointer (`SP`) and `A11` is the Return Address (`RA`).
- **Memory Addressing:** Linear 32-bit address space (4 GiB), divided into sixteen 256 MiB segments (`0x0` through `0xF`).

```
+-------------------------------------------------------------+
|                      TriCore Memory Map                     |
+-------------------+--------------------+--------------------+
| Segment           | Address Range      | Description        |
+-------------------+--------------------+--------------------+
| Segment 8 (Cached)| 0x80000000 - 0x801FFFFF | Program Flash (PFLASH)   |
| Segment A (Non-C) | 0xA0000000 - 0xA01FFFFF | PFLASH (Mirror/Non-Cache)|
| Segment A (DFLASH)| 0xAF000000 - 0xAF01FFFF | Data Flash (DFLASH/EEPR) |
| Segment D (DSPR)  | 0xD0000000 - 0xD001FFFF | Data Scratchpad RAM      |
| Segment C (PSPR)  | 0xC0000000 - 0xC0007FFF | Program Scratchpad RAM   |
| Segment F (MMIO)  | 0xF8000000 - 0xFFFFFFFF | Core & Peripheral SFRs   |
+-------------------+--------------------+--------------------+
```

---

## 2. Binary Layout & Base Address Discovery

When loading a flat firmware binary dump (e.g., a 1.5 MiB or 2.0 MiB `.bin` file) into a disassembler like **Ghidra**, there is no header specifying the base load address. Attempting to disassemble from `0x00000000` results in invalid operand references and unresolvable pointer targets.

### Vector Table Analysis
On TriCore architectures, the Reset Vector and BootROM transition pointers are located at the start of the Flash mirror or at an architected offset defined by the Boot Configuration:

1. **Locating the Entry Point:**
   In raw firmware images, the first 32 to 64 bytes contain the hardware configuration word and reset handler branch:
   ```text
   Hex dump at offset 0x00000000:
   00000000: 00 00 00 80 00 00 00 00  ...
   ```
   Or an immediate jump instruction:
   ```assembly
   LEA.A    A10, 0xD0008000    ; Initialize Stack Pointer to DSPR
   JA       0x80000100         ; Absolute Jump to Reset Initialization
   ```

2. **Pointer Correlation Method:**
   To verify the base address programmatically without prior knowledge:
   - Scan the binary for 32-bit little-endian words matching `0x80XXXXXX` or `0xA0XXXXXX`.
   - Compute candidate offsets: `Candidate_Offset = Found_Pointer - File_Position`.
   - If a significant cluster of pointers consistently references internal string tables or function prologues under the assumption that `File_Offset 0x00000000 = Memory 0x80000000`, the image base is verified.

---

## 3. Disassembly & Static Analysis in Ghidra

### Processor Module Selection
- **Language:** `TriCore:LE:32:default` (Little-Endian 32-bit).
- **Memory Blocks Configuration:**
  1. Map `PFLASH` from `0x80000000` to `0x801FFFFF` (Read + Execute).
  2. Map `PFLASH_MIRROR` from `0xA0000000` to `0xA01FFFFF` (Read + Execute).
  3. Map `DSPR` (Scratchpad RAM) from `0xD0000000` to `0xD001FFFF` (Read + Write).
  4. Map `MMIO` registers from `0xF8000000` to `0xFFFFFFFF` (Volatile Read + Write).

### Identifying Function Calling Conventions
TriCore uses a specialized register-passing convention:
- Parameters are passed in `D4`–`D7` (data) and `A4`–`A7` (pointers).
- Return values are returned in `D2` (or `A2` for pointers).
- Context saving is handled automatically by hardware instructions (`SVLCX` / `RSLCX` for lower context, and `B` / `CALL` for upper context).

---

## 4. Automotive Diagnostic Protocol Demultiplexing

ECU software integrates standardized automotive diagnostic stacks (ISO 14229 / UDS). Reverse engineering these dispatcher tables exposes the operational surface of the ECU.

```
                    +-----------------------------+
                    |    Incoming CAN Frame       |
                    | (Standard ID: 0x7E0 / 0x7E8)|
                    +--------------+--------------+
                                   |
                                   v
                    +-----------------------------+
                    | ISO-TP (ISO 15765-2) Layer  |
                    | Frame Reassembly & Flow Ctrl|
                    +--------------+--------------+
                                   |
                                   v
                    +-----------------------------+
                    |   UDS (ISO 14229) Dispatch  |
                    | Switch on Service ID (SID)  |
                    +--------------+--------------+
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
         v                         v                         v
+-----------------+       +-----------------+       +-----------------+
| SID 0x10:       |       | SID 0x27:       |       | SID 0x22 / 0x23:|
| Session Control |       | Security Access |       | Read Data / Mem |
| (Default/Prog)  |       | (Seed/Key PRNG) |       | (DIDs / Tables) |
+-----------------+       +-----------------+       +-----------------+
```

### Locating the UDS Dispatch Table
The UDS service dispatcher is typically implemented as an array of structs:
```c
typedef struct {
    uint8_t service_id;          // e.g., 0x10, 0x22, 0x27, 0x34
    uint8_t allowed_sessions;    // Bitmask for Default, Programming, Extended
    uint8_t security_level;      // Required authentication level
    void (*handler_func)(void);  // Pointer to service routine
} UdsServiceDescriptor;
```
By searching for consecutive bytes corresponding to standard UDS services (`10 22 23 27 2E 31 3E`), the primary command handler table and its corresponding function pointers can be isolated in Ghidra.

---

## 5. Calibration Maps & Flash Structuring

ECU firmware binaries consist of two primary logical partitions:
1. **Application Executable Code (Code Flash):** Contains the compiled engine management control algorithms, ignition timing loops, air-fuel ratio PID controllers, and CAN communication drivers.
2. **Calibration Data (Cal Flash):** Stores scalar parameters, 1D transfer functions (curves), and 2D look-up tables (maps) defining engine operational dynamics.

### Anatomy of an ECU Look-Up Table
Unlike standard C arrays, automotive calibration tables (standardized by ASAM MCD-2MC / A2L) include axis descriptor metadata:
- **Axis Definition:** Number of breakpoints, data type (uint8, uint16, IEEE-754 float), and scaling factors.
- **Reference Pointers:** Pointers to the input sensor variables (e.g., Engine RPM `0xD0002140`, Manifold Absolute Pressure `0xD0002144`).
- **Data Table:** Contiguous memory block containing interpolated output values (e.g., spark advance angle in degrees BTDC).

---

## 6. Checksum & Integrity Algorithms

Automotive microcontrollers enforce checksum validation during both the boot phase and when writing new flash blocks:
- **Block Checksums:** 16-bit or 32-bit CRC (e.g., CRC32-AUTOSAR) calculated over defined flash ranges.
- **Additive Complement Checksum:** A sum of all 16-bit or 32-bit words within a sector, where the stored checksum value is calculated such that `Sum(Sector_Words) + Checksum == 0x00000000`.

Finding the checksum validation routines in Ghidra allows understanding the verification bounds and memory range boundaries monitored by the ECU bootloader.

---

## 7. Educational & Research Conclusions

Static analysis of raw embedded automotive firmware demonstrates core computer science principles in practice:
- **Processor architecture understanding** (register conventions, memory segmentation, MMIO bus mapping).
- **Communication stack implementation** (packet segmentation, state machines, protocol dispatchers).
- **Algorithm verification** (real-time lookups, fixed-point interpolation, checksum integrity).

Developing independent, open-source diagnostic utilities (such as Python + `libusb` diagnostic implementations) bridges low-level hardware reversing with high-level software engineering on Linux.

---

## Summary & Future Work

These notes serve as a technical engineering log documenting the methodology for understanding embedded bare-metal automotive binaries, memory organization, and protocol stacks.

