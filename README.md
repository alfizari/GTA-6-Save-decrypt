# GTA VI Save Tool

Decrypt, edit, and re-encrypt GTA VI save files (SARC / ASAV v1, storage mode 3).

## What it does

- **Decrypt**: SARC save file -> JSON body (+ optional raw JSAV dump)
- **Encrypt**: Edited JSON body (or JSAV binary) + original SARC as template -> new SARC save file
- Handles the full pipeline: AES-256-CTR, PKCS#7 padding, LZ4, JSAV parsing, header checksum, and the 32-byte integrity trailer (all in pure Python)

## Requirements

- **Python 3.8+** (the tool runs on the standard library alone)
- **lz4** (optional, faster compression): `pip install lz4`
- **cryptography** (optional, faster AES): `pip install cryptography`

No DLL, C helper, lookup blob, or game exe is needed. All cipher tables, the LZ4 codec, and the integrity trailer are implemented directly in `gta6_save_tool.py`.

## Files

| File | Description |
|------|-------------|
| `gta6_save_tool.py` | The whole tool (GUI + CLI), pure Python |
| `build.bat` | Builds a standalone `gta6_save_tool.exe` with PyInstaller |

## Setup

1. Copy `gta6_save_tool.py` anywhere.
2. Optionally install the speed-ups: `pip install lz4 cryptography`

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

## Building a standalone exe

`build.bat` packages the tool into a single `gta6_save_tool.exe` with PyInstaller, so it can run on a PC without Python installed.

1. Install Python 3.8+ and make sure `python` (or `py`) is on PATH.
2. Double-click `build.bat`, or run it from a command prompt in the tool's folder:
   ```
   build.bat
   ```
   It installs/updates `pyinstaller`, `lz4` and `cryptography`, then builds.
3. The exe is written to `dist\gta6_save_tool.exe`.

The default build is a console exe: double-clicking it opens the GUI, and it also accepts the same CLI arguments:
```
gta6_save_tool.exe decrypt SARC0003 output.json
gta6_save_tool.exe encrypt body.json SARC0003_original SARC0003_new
```

For a GUI-only exe without the console window, run `build.bat nocon`. That build cannot show CLI output, so use the default build for command-line use.

Manual equivalent:
```
python -m pip install pyinstaller lz4 cryptography
python -m PyInstaller --onefile --console --name gta6_save_tool --hidden-import lz4.block --collect-submodules cryptography gta6_save_tool.py
```

Thanks to [@earthonion](https://github.com/earthonion) for the checksum fixes.
