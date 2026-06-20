# Steam Client Pattern Update Guide

This guide describes how to troubleshoot, find, and update byte-pattern signatures for `steamclient64.dll` and `steamui.dll` when a Steam client update breaks them.

> [!NOTE]
> **Quick Start**: run the scanner against your Steam install directory:
> ```powershell
> .\pattern_scanner.exe "C:\Program Files (x86)\Steam" .\output
> ```
> Each generated `.toml` file is named after the SHA-256 hash of the scanned DLL,
> matching the structure expected by `steam-monitor`.


## 1. Quick Tweak via AI (LLM)

If a signature fails to match, but you have the disassembly of the old function and the new function, you can ask an AI to construct or tweak the signature.

### Prompt Template for AI

Copy and paste the following prompt into an LLM (e.g. Gemini, ChatGPT, Claude) to update a broken pattern:

```text
You are a reverse engineering assistant. I need to update a byte-pattern signature for a function in a Windows x64 DLL. 

The function's name is: <Function Name>
The old signature was: <Old Signature>
The old disassembly of the function's entry was:
<Paste old disassembly or assembly instructions here>

In the new DLL version, this function has been modified slightly. Here is the new disassembly of the function's entry:
<Paste new disassembly or assembly instructions here>

Please:
1. Compare the two disassemblies.
2. Identify why the old signature failed (e.g., changes in registers, stack allocations, or relative offsets).
3. Generate a new IDA-style byte-pattern signature (space-separated hex bytes, using '??' for wildcards on variable fields like relative offsets, stack displacements, or changed registers). Make sure the signature is long enough to be unique (typically 15-30 bytes).
```

---

## 2. Dynamic Analysis with x64dbg

x64dbg is a very fast tool for finding updated functions live or statically in memory.

### Step-by-Step Guide
1. **Locate a reference**:
   - Look at the console warning in `OpenSteamTool` or this pattern generator to see which function failed.
   - If you have an existing older `steamclient64.dll`, open it in x64dbg. Locate the function (e.g., via string references or exports).
2. **Search for Strings**:
   - In the **CPU** tab, right-click -> **Search for** -> **All Modules** (or Current Module) -> **String References**.
   - Search for strings near the function (e.g., logging strings like `BBuildAndAsyncSendFrame` or `opt-in`).
   - Double-click the string to go to the address, and scroll up to the function prologue.
3. **Analyze the Prologue**:
   - The beginning of the function is usually characterized by instructions like:
     - `mov [rsp+...], reg`
     - `push rbp` / `push rdi`
     - `sub rsp, <size>`
4. **Extract Hex Bytes**:
   - Highlight the first few instructions of the function (aim for ~15 to 25 bytes).
   - Right-click the highlighted lines -> **Binary** -> **Copy Hex** (or Copy Pattern).
5. **Wildcarding Variable Fields**:
   - Replace any relative branch displacements, relative data offsets, or stack offsets that might change from compilation to compilation with `??`.
   - *Example*: `48 8D 05 12 34 56 07` (loading a RIP-relative pointer) should be wildcarded to `48 8D 05 ?? ?? ?? ??`.

---

## 3. Static Analysis with Ghidra

Ghidra is a free, open-source software reverse engineering suite.

### Step-by-Step Guide
1. Import `steamclient64.dll` into Ghidra and run the default analysis.
2. **Find Reference Strings**:
   - Search -> **Program Text** or Search -> **For Strings...**
   - Look up strings printed near your target function.
3. **Trace to Function Entry**:
   - Go to the cross-reference (XREF) of the string to find the function calling it or referencing it.
   - Click on the function header in the Listing view.
4. **Get Bytes**:
   - In the Listing view, look at the hex bytes column next to the assembly instructions.
   - Copy the hex bytes from the function start.
5. **Mask Relocations**:
   - Identify instructions containing addresses or offsets (e.g., `CALL`, `JMP`, `MOV RAX, [DAT_...]`).
   - Replace the parts of the byte sequence that represent these addresses/offsets with `??`.
   - *Tip*: Check the bytes in Ghidra's "Bytes" view to confirm which ones correspond to offsets.

---

## 4. Static Analysis with Binary Ninja

Binary Ninja is a commercial reverse-engineering tool known for its clean UI and Intermediate Language (IL).

### Step-by-Step Guide
1. Open `steamclient64.dll` in Binary Ninja.
2. **String Search**:
   - Use the **Strings** sidebar (or press `Ctrl+Shift+S`) to search for strings that are used inside or near the function.
   - Double-click the string and use `X` to view cross-references to trace back to the function.
3. **Generate Signature**:
   - Select the starting range of the function.
   - Look at the hex representation in the status bar or Hex View.
   - You can use the community plugin **SigKit** to automatically generate an IDA-style signature with wildcards for selected instructions.
4. **Manual Wildcarding**:
   - Mask constant values that change due to offsets (like references to the global offset tables or relative jumps) by replacing them with `??`.

---

## 5. Static Analysis with IDA Pro

IDA Pro is the industry standard disassembler.

### Step-by-Step Guide
1. Load `steamclient64.dll` into IDA Pro and wait for the auto-analysis to finish.
2. **Search for Strings**:
   - Press `Shift+F12` to open the Strings window.
   - Search for a relevant string name.
   - Double-click it and press `X` on its address to find the referencing function.
3. **Use SigMaker Plugin (Recommended)**:
   - Go to the start of the function.
   - Select the first few lines of the function.
   - Run the **SigMaker** plugin (`Edit` -> `Plugins` -> `Make Signature`).
   - SigMaker will automatically generate a unique, minimal signature with `??` wildcards.
4. **Manual Signature**:
   - If SigMaker is not installed, open the **Hex View** synchronized with the **IDA View-A**.
   - Copy the first ~20 bytes.
   - Identify relocatable targets (red-colored bytes in IDA) and replace them with `??` in your signature string.

---

## 6. Functions That Cannot Be Found by Pattern Scanning

Some very short functions (2–4 instructions) produce signatures so generic that they match hundreds of unrelated locations in the binary. The scanner skips these and documents them here.

### `GetTopManager` (steamui)

`GetTopManager` is a 2-instruction stub:
```asm
mov rax, [rip + <global_ptr>]
ret
```
The 8-byte pattern `48 8B 05 XX XX XX XX C3` matches many locations in `steamui.dll`. The actual bytes at positions 3–6 are a RIP-relative pointer offset into a global — this changes every Steam update so it **cannot** be wildcarded.

**How to find it via cross-reference:**
1. In Ghidra/IDA/Binary Ninja, navigate into `CSteamUIAppControllerRunFrame` (you can find this via its unique signature).
2. Look at the very first `CALL` instruction — its target is `GetTopManager`.
3. Note the target address, compute the RVA as `address - imageBase`.
4. Copy the **exact 8 bytes** (`48 8B 05 XX XX XX XX C3`) verbatim — do **not** wildcard `XX XX XX XX`.

**Entry to add manually to the TOML:**
```toml
[0xC89CFA75]
name = "GetTopManager"
rva = "0x<hex_rva>"
sig = "48 8B 05 XX XX XX XX C3"
```

---

## 7. Full Workflow: After a Steam Update

1. Run the scanner:
   ```powershell
   .\pattern_scanner.exe "C:\Program Files (x86)\Steam" .\output
   ```
2. Check the console for any `[WARNING] Could not find pattern for function:` lines.
3. For each warning, use sections 1–5 above to locate the new function and build a new signature.
4. Add the new signature to the `sigs` array inside `main.rs` for the relevant function definition.
5. Rebuild: `cargo build --release`
6. Re-run the scanner to confirm the warning is gone.
7. Upload the generated `steamclient/<sha256>.toml` and `steamui/<sha256>.toml` files to the appropriate branches of `steam-monitor`.
