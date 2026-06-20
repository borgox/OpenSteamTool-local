import os
import sys
import re
import struct
import hashlib
import argparse
from google.protobuf import descriptor_pb2

# --- Common PE Parsing Helpers ---

class PESection:
    def __init__(self, name, vaddr, raw_size, raw_ptr):
        self.name = name
        self.vaddr = vaddr
        self.raw_size = raw_size
        self.raw_ptr = raw_ptr

def parse_pe_sections(data):
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise ValueError("Invalid DOS header")
    pe_offset = int.from_bytes(data[0x3c:0x40], "little")
    if len(data) < pe_offset + 24 or data[pe_offset:pe_offset+4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    
    num_sections = int.from_bytes(data[pe_offset+6:pe_offset+8], "little")
    opt_header_size = int.from_bytes(data[pe_offset+20:pe_offset+22], "little")
    magic = int.from_bytes(data[pe_offset+24:pe_offset+26], "little")
    
    if magic == 0x20b: # PE32+ (64-bit)
        image_base = int.from_bytes(data[pe_offset+24+24:pe_offset+24+32], "little")
    else:
        image_base = int.from_bytes(data[pe_offset+24+28:pe_offset+24+32], "little")
        
    sec_table_offset = pe_offset + 24 + opt_header_size
    sections = []
    for i in range(num_sections):
        offset = sec_table_offset + i * 40
        sec_data = data[offset:offset+40]
        name = sec_data[0:8].decode("utf-8", errors="ignore").strip("\x00")
        vaddr = int.from_bytes(sec_data[12:16], "little")
        raw_size = int.from_bytes(sec_data[16:20], "little")
        raw_ptr = int.from_bytes(sec_data[20:24], "little")
        sections.append(PESection(name, vaddr, raw_size, raw_ptr))
        
    return image_base, sections

def get_sha256(data):
    return hashlib.sha256(data).hexdigest()

# --- IPC Generator Logic ---

IPC_TARGETS = {
    "IClientUser": {
        "id": 1,
        "methods": {
            "GetSteamID": {"index": 10, "hash": 0xD6FC3200, "fence": 0xD7058CA5, "argc": 0},
            "GetAppOwnershipTicketExtendedData": {"index": 105, "hash": 0xC7E71245, "fence": 0xC8449840, "argc": 2},
            "RequestEncryptedAppTicket": {"index": 120, "hash": 0x25D6BB1D, "fence": 0x2646B663, "argc": 2},
            "GetEncryptedAppTicket": {"index": 121, "hash": 0xE0468CB4, "fence": 0xE0B80200, "argc": 1}
        }
    },
    "IClientUtils": {
        "id": 4,
        "methods": {
            "GetAppID": {"index": 19, "hash": 0x09607EC4, "fence": 0x0AFE7552, "argc": 0},
            "GetAPICallResult": {"index": 24, "hash": 0x2D3D3947, "fence": 0x2EDF5EE6, "argc": 3}
        }
    }
}

def generate_ipc(dll_path, output_dir):
    with open(dll_path, "rb") as f:
        data = f.read()
        
    sha256 = get_sha256(data)
    print(f"File SHA-256: {sha256}")
    
    image_base, sections = parse_pe_sections(data)
    
    text_sec = next((s for s in sections if s.name == ".text"), None)
    rdata_sec = next((s for s in sections if s.name == ".rdata"), None)
    
    if not text_sec or not rdata_sec:
        raise ValueError("DLL missing .text or .rdata section")
        
    def rva_to_offset(rva):
        for s in sections:
            if s.vaddr <= rva < s.vaddr + s.raw_size:
                return s.raw_ptr + (rva - s.vaddr)
        return None

    def offset_to_rva(offset):
        for s in sections:
            if s.raw_ptr <= offset < s.raw_ptr + s.raw_size:
                return s.vaddr + (offset - s.raw_ptr)
        return None

    # Find method bodies in .text
    resolved_bodies = {}
    for iface, iface_data in IPC_TARGETS.items():
        resolved_bodies[iface] = {}
        for method, m_info in iface_data["methods"].items():
            hash_bytes = struct.pack("<I", m_info["hash"])
            fence_bytes = struct.pack("<I", m_info["fence"])
            
            offset = text_sec.raw_ptr
            text_end = text_sec.raw_ptr + text_sec.raw_size
            found_rva = None
            while True:
                pos = data.find(hash_bytes, offset, text_end)
                if pos == -1:
                    break
                # Check fencepost nearby
                context = data[pos:pos+128]
                if fence_bytes in context:
                    found_rva = offset_to_rva(pos)
                    break
                offset = pos + 1
            resolved_bodies[iface][method] = found_rva

    # Read pointers from .rdata
    rdata_ptrs = []
    for offset in range(rdata_sec.raw_ptr, rdata_sec.raw_ptr + rdata_sec.raw_size - 8, 8):
        ptr = int.from_bytes(data[offset:offset+8], "little")
        rdata_ptrs.append((offset, ptr - image_base))

    # Resolve vtables
    resolved_vtables = {}
    for iface, iface_data in IPC_TARGETS.items():
        primary_method = list(iface_data["methods"].keys())[0]
        primary_info = iface_data["methods"][primary_method]
        match_rva = resolved_bodies[iface][primary_method]
        
        if not match_rva:
            print(f"Warning: Primary method {iface}::{primary_method} not resolved in binary.")
            continue
            
        candidates = []
        for offset, rva in rdata_ptrs:
            if match_rva - 256 <= rva <= match_rva:
                vtable_base_offset = offset - primary_info["index"] * 8
                candidates.append(vtable_base_offset)
                
        for vtable_offset in candidates:
            vtable_rva = offset_to_rva(vtable_offset)
            if vtable_rva is None:
                continue
            
            # Verify all methods in the vtable
            verified = True
            methods_rva = {}
            for method, m_info in iface_data["methods"].items():
                m_offset = vtable_offset + m_info["index"] * 8
                if m_offset + 8 > rdata_sec.raw_ptr + rdata_sec.raw_size:
                    verified = False
                    break
                ptr_val = int.from_bytes(data[m_offset:m_offset+8], "little")
                m_rva = ptr_val - image_base
                expected_rva = resolved_bodies[iface][method]
                if not expected_rva or not (expected_rva - 256 <= m_rva <= expected_rva):
                    verified = False
                    break
                methods_rva[method] = m_rva
                
            if verified:
                resolved_vtables[iface] = {
                    "vtable_rva": vtable_rva,
                    "methods": methods_rva
                }
                break

    # Format TOML output
    toml_lines = []
    for iface, iface_data in IPC_TARGETS.items():
        if iface not in resolved_vtables:
            print(f"Warning: Could not resolve vtable for {iface}")
            continue
        v_info = resolved_vtables[iface]
        toml_lines.append(f"[{iface}]")
        toml_lines.append(f"interface_id = {iface_data['id']}")
        toml_lines.append(f'vtable_rva = "0x{v_info["vtable_rva"]:X}"')
        toml_lines.append("")
        
        for method, m_info in iface_data["methods"].items():
            toml_lines.append(f"[{iface}.{method}]")
            toml_lines.append(f"method_index = {m_info['index']}")
            toml_lines.append(f'funcHash = "0x{m_info["hash"]:08X}"')
            toml_lines.append(f'wrapper_rva = "0x{v_info["methods"][method]:X}"')
            toml_lines.append(f'fencepost = "0x{m_info["fence"]:08X}"')
            toml_lines.append(f"argc = {m_info['argc']}")
            toml_lines.append("")
            
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"{sha256}.toml")
    with open(out_path, "w") as f:
        f.write("\n".join(toml_lines))
    print(f"Written to cache: {out_path}")

# --- Protobuf Extractor Logic ---

TYPE_MAP = {
    descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE: "double",
    descriptor_pb2.FieldDescriptorProto.TYPE_FLOAT: "float",
    descriptor_pb2.FieldDescriptorProto.TYPE_INT64: "int64",
    descriptor_pb2.FieldDescriptorProto.TYPE_UINT64: "uint64",
    descriptor_pb2.FieldDescriptorProto.TYPE_INT32: "int32",
    descriptor_pb2.FieldDescriptorProto.TYPE_FIXED64: "fixed64",
    descriptor_pb2.FieldDescriptorProto.TYPE_FIXED32: "fixed32",
    descriptor_pb2.FieldDescriptorProto.TYPE_BOOL: "bool",
    descriptor_pb2.FieldDescriptorProto.TYPE_STRING: "string",
    descriptor_pb2.FieldDescriptorProto.TYPE_BYTES: "bytes",
    descriptor_pb2.FieldDescriptorProto.TYPE_UINT32: "uint32",
    descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED32: "sfixed32",
    descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED64: "sfixed64",
    descriptor_pb2.FieldDescriptorProto.TYPE_SINT32: "sint32",
    descriptor_pb2.FieldDescriptorProto.TYPE_SINT64: "sint64",
}

LABEL_MAP = {
    descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL: "optional",
    descriptor_pb2.FieldDescriptorProto.LABEL_REQUIRED: "required",
    descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED: "repeated",
}

def format_descriptor_to_proto(fd):
    lines = []
    # Syntax
    syntax = fd.syntax if fd.syntax else "proto2"
    lines.append(f'syntax = "{syntax}";')
    lines.append("")
    
    # Imports
    for dep in fd.dependency:
        lines.append(f'import "{dep}";')
    if fd.dependency:
        lines.append("")
        
    # Package
    if fd.package:
        lines.append(f'package {fd.package};')
        lines.append("")
        
    # File options
    if fd.HasField("options"):
        opts = fd.options
        val = "true" if opts.cc_generic_services else "false"
        lines.append(f"option cc_generic_services = {val};")
        speed_map = {1: "SPEED", 2: "CODE_SIZE", 3: "LITE_RUNTIME"}
        lines.append(f"option optimize_for = {speed_map.get(opts.optimize_for, 'SPEED')};")
        lines.append("")

    def format_fields(fields, indent):
        field_lines = []
        for field in fields:
            label_str = ""
            if field.label in LABEL_MAP:
                if syntax == "proto3" and field.label == descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL:
                    label_str = ""
                else:
                    label_str = LABEL_MAP[field.label] + " "
                    
            if field.type in TYPE_MAP:
                type_str = TYPE_MAP[field.type]
            elif field.type in (descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, descriptor_pb2.FieldDescriptorProto.TYPE_ENUM):
                type_str = field.type_name.lstrip(".")
            else:
                type_str = "unknown"
                
            opts_list = []
            if field.HasField("default_value"):
                if field.type == descriptor_pb2.FieldDescriptorProto.TYPE_STRING:
                    opts_list.append(f'default = "{field.default_value}"')
                else:
                    opts_list.append(f'default = {field.default_value}')
            if field.options and field.options.HasField("packed"):
                val = "true" if field.options.packed else "false"
                opts_list.append(f"packed = {val}")
                
            opts_str = f" [{', '.join(opts_list)}]" if opts_list else ""
            field_lines.append(f"{indent}{label_str}{type_str} {field.name} = {field.number}{opts_str};")
        return field_lines

    def format_enum(enum, indent):
        enum_lines = []
        enum_lines.append(f"{indent}enum {enum.name} {{")
        for val in enum.value:
            enum_lines.append(f"{indent}    {val.name} = {val.number};")
        enum_lines.append(f"{indent}}}")
        return enum_lines

    def format_message(msg, indent):
        msg_lines = []
        msg_lines.append(f"{indent}message {msg.name} {{")
        
        for enum in msg.enum_type:
            msg_lines.extend(format_enum(enum, indent + "    "))
            msg_lines.append("")
            
        for nested in msg.nested_type:
            msg_lines.extend(format_message(nested, indent + "    "))
            msg_lines.append("")
            
        msg_lines.extend(format_fields(msg.field, indent + "    "))
        msg_lines.append(f"{indent}}}")
        return msg_lines

    for enum in fd.enum_type:
        lines.extend(format_enum(enum, ""))
        lines.append("")
        
    for msg in fd.message_type:
        lines.extend(format_message(msg, ""))
        lines.append("")
        
    for svc in fd.service:
        lines.append(f"service {svc.name} {{")
        for method in svc.method:
            input_type = method.input_type.lstrip(".")
            output_type = method.output_type.lstrip(".")
            lines.append(f"    rpc {method.name}({input_type}) returns ({output_type});")
        lines.append("}")
        lines.append("")
        
    return "\n".join(lines)

def extract_protobufs(dll_path, output_dir):
    with open(dll_path, "rb") as f:
        data = f.read()
        
    proto_re = re.compile(rb'[a-zA-Z0-9_\-\.]+\.proto')
    extracted_count = 0
    os.makedirs(output_dir, exist_ok=True)
    
    for match in proto_re.finditer(data):
        filename = match.group()
        pos = match.start()
        
        if pos >= 2:
            tag_byte = data[pos-2]
            len_byte = data[pos-1]
            if tag_byte == 0x0A and len_byte == len(filename):
                start = pos - 2
                best_fd = None
                best_size = None
                
                consecutive_failures = 0
                size = len(filename) + 2
                while consecutive_failures < 256:
                    try:
                        fd = descriptor_pb2.FileDescriptorProto()
                        fd.ParseFromString(data[start:start+size])
                        if fd.name == filename.decode():
                            if len(fd.message_type) > 0 or len(fd.enum_type) > 0 or len(fd.service) > 0:
                                best_fd = fd
                                best_size = size
                                consecutive_failures = 0
                            else:
                                consecutive_failures += 1
                        else:
                            consecutive_failures += 1
                    except Exception:
                        consecutive_failures += 1
                    size += 1
                
                if best_fd:
                    proto_text = format_descriptor_to_proto(best_fd)
                    out_file = os.path.join(output_dir, best_fd.name)
                    with open(out_file, "w") as out_f:
                        out_f.write(proto_text)
                    extracted_count += 1
                    
    print(f"Extracted {extracted_count} protobuf files into {output_dir}")

# --- Helpers ---

def _steam_cache_root(dll_path):
    """Given a DLL path, return <steam_root>/opensteamtool/."""
    return os.path.join(os.path.dirname(dll_path), "opensteamtool")

# --- CLI Setup ---

def main():
    parser = argparse.ArgumentParser(
        description="Steam Monitor Metadata & Protobuf Generator Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
When output_dir is omitted the tool writes directly into the OpenSteamTool
cache tree inside the Steam installation directory so the loader picks up
the files automatically on the next Steam launch:

  ipc      -> <Steam>/opensteamtool/ipc/steamclient/<sha256>.toml
  protobuf -> <Steam>/opensteamtool/protobuf/<component>/<name>.proto
  pattern  -> written by pattern_scanner, not this tool
  all      -> all of the above, derived from the Steam directory
"""
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # IPC Command
    ipc_parser = subparsers.add_parser("ipc", help="Generate IPC TOML file from steamclient64.dll")
    ipc_parser.add_argument("dll_path", help="Path to steamclient64.dll")
    ipc_parser.add_argument("output_dir", nargs="?", default=None,
                            help="Output directory (default: <Steam>/opensteamtool/ipc/steamclient/)")
    
    # Protobuf Command
    proto_parser = subparsers.add_parser("protobuf", help="Extract all embedded .proto files from DLL")
    proto_parser.add_argument("dll_path", help="Path to steamclient64.dll or steamui.dll")
    proto_parser.add_argument("output_dir", nargs="?", default=None,
                              help="Output directory (default: <Steam>/opensteamtool/protobuf/<component>/)")
    
    # All Command
    all_parser = subparsers.add_parser("all", help="Extract both IPC and Protobuf definitions from a Steam installation")
    all_parser.add_argument("steam_dir", help="Path to Steam root installation directory")
    all_parser.add_argument("output_dir", nargs="?", default=None,
                            help="Output root (default: <steam_dir>/opensteamtool/)")
    
    args = parser.parse_args()
    
    try:
        if args.command == "ipc":
            if args.output_dir:
                out = args.output_dir
            else:
                # Default: <steam_root>/opensteamtool/ipc/steamclient/
                out = os.path.join(_steam_cache_root(args.dll_path), "ipc", "steamclient")
                print(f"No output_dir given — writing to cache: {out}")
            generate_ipc(args.dll_path, out)

        elif args.command == "protobuf":
            dll_name = os.path.splitext(os.path.basename(args.dll_path))[0].lower()
            component = "steamui" if "steamui" in dll_name else "steamclient"
            if args.output_dir:
                out = args.output_dir
            else:
                out = os.path.join(_steam_cache_root(args.dll_path), "protobuf", component)
                print(f"No output_dir given — writing to cache: {out}")
            extract_protobufs(args.dll_path, out)

        elif args.command == "all":
            cache_root = os.path.join(args.steam_dir, "opensteamtool") if not args.output_dir \
                         else args.output_dir
            if not args.output_dir:
                print(f"No output_dir given — writing to cache root: {cache_root}")

            client_path = os.path.join(args.steam_dir, "steamclient64.dll")
            ui_path = os.path.join(args.steam_dir, "steamui.dll")

            if not os.path.exists(client_path):
                raise FileNotFoundError(f"steamclient64.dll not found in {args.steam_dir}")

            print(f"Scanning {client_path} for IPC definitions...")
            generate_ipc(client_path, os.path.join(cache_root, "ipc", "steamclient"))

            print(f"Scanning {client_path} for Protobuf definitions...")
            extract_protobufs(client_path, os.path.join(cache_root, "protobuf", "steamclient"))

            if os.path.exists(ui_path):
                print(f"Scanning {ui_path} for Protobuf definitions...")
                extract_protobufs(ui_path, os.path.join(cache_root, "protobuf", "steamui"))
            else:
                print("steamui.dll not found, skipping UI protobuf extraction.")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
