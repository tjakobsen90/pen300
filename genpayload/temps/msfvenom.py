payloads = {
    "windows": {
        "x86": {
            "secure": "windows/meterpreter/reverse_winhttps",
            "tcp": "windows/meterpreter/reverse_tcp",
            "basic": "windows/shell/reverse_tcp",
        },
        "x64": {
            "secure": "windows/x64/meterpreter/reverse_winhttps",
            "tcp": "windows/x64/meterpreter/reverse_tcp",
            "basic": "windows/x64/shell/reverse_tcp",
        },
    },
    "linux": {
        "x86": {
            "tcp": "linux/x86/meterpreter/reverse_https",
            "basic": "linux/x86/shell/reverse_tcp",
        },
        "x64": {
            "tcp": "linux/x64/meterpreter/reverse_tcp",
            "basic": "linux/x64/shell/reverse_tcp",
        },
    },
}
