# GTA VI Save Tool

The tag is not calculated so it will corrupt the save file, will fix it soon

Decrypt, edit, and re-encrypt GTA VI save files (SARC / ASAV v1, storage mode 3).

## What it does

- **Decrypt**: SARC save file -> JSON body (+ optional raw JSAV dump)
- **Encrypt**: Edited JSON body (or JSAV binary) + original SARC as template -> new SARC save file
- Handles the full pipeline: AES-CTR decryption, LZ4 decompression, JSAV parsing, header checksum, and trailing authentication tag

## Requirements

- **Python 3.8+**
- **lz4** (optional but recommended for faster compression):
  ```
  pip install lz4
  ```
- **Tag generation** (one of):
  - `gta6_tag.dll` + `gta6_tag_blob.bin` (small standalone helper, recommended)
  - Or the full game executable (120+ MB, not recommended)

## Files

| File | Description |
|------|-------------|
| `gta6_save_tool.py` | Main tool (GUI + CLI) — self-contained cipher tables |
| `gta6_tag.dll` | Standalone tag/signing helper (~1 MB) |
| `gta6_tag_blob.bin` | Lookup tables used by the DLL |
| `gta6_tag.c` | C source for the DLL (if you want to rebuild) |
| `build_helper.bat` | Build script for the DLL (requires MSVC) |

## Setup

1. Place these files in the same folder:
   - `gta6_save_tool.py`
   - `gta6_tag.dll`
   - `gta6_tag_blob.bin`

2. Install the optional lz4 package:
   ```
   pip install lz4
   ```

3. That's it. No other dependencies needed — cipher tables are embedded in the Python script.

## Usage

### GUI mode

```
python gta6_save_tool.py
```

Opens a window where you can select Decrypt or Encrypt mode, pick input/output files, and run the operation with a progress bar and log output.

### Command-line mode

**Decrypt** a save to JSON:
```
python gta6_save_tool.py decrypt SARC0003 output.json
```

**Encrypt** an edited JSON back into a save:
```
python gta6_save_tool.py encrypt body.json SARC0003_original SARC0003_new
```

Arguments for encrypt:
1. The edited JSON body (or `.jsav.bin` file)
2. The original SARC save (used as a template for header/trailer)
3. Output path for the new save

## Typical workflow

1. **Decrypt** your save file to get the JSON body
2. **Edit** the JSON (player stats, inventory, progress, etc.)
3. **Encrypt** the edited JSON using the original save as a template
4. The tool automatically recomputes the LZ4 compression, AES-CTR encryption, header checksum, and authentication tag
5. Replace the save file and load in-game

## Rebuilding the DLL from source

Requires Visual Studio with C++ build tools (MSVC x64).

**Option A** — double-click `build_helper.bat`

**Option B** — from an x64 Native Tools Command Prompt:
```
cl /nologo /O2 /LD gta6_tag.c /Fe:gta6_tag.dll
```

Keep `gta6_tag_blob.bin` in the same directory as the built DLL.
