#!/usr/bin/python3

from langs import clang
from lib.functions import parse_arguments, list_options
from langs import csharp, jscript, powershell, vbapplication
from contextlib import contextmanager


def main():
    args = parse_arguments()

    if args.format == "c" and args.template in ["elf", "so-libpath", "so-preload"]:
        clang.main(args)
    elif args.format == "cs" and args.template in ["exe", "dll", "exe-ph", "dll-ph", "exe-nomigrate", "dll-nomigrate", "aspx"]:
        csharp.main(args)
    elif args.format == "js" and args.template in ["hta", "xsl"]:
        with temporarily_set_template(args, "js"):
            csharp.main(args)
        jscript.main(args)
    elif args.format == "js" and args.template in ["hta-ph", "xsl-ph"]:
        with temporarily_set_template(args, "js-ph"):
            csharp.main(args)
        jscript.main(args)
    elif args.format == "ps" and args.template in ["default", "ph"]:
        powershell.main(args)
    elif args.format == "vba" and args.template in ["basic", "default"]:
        vbapplication.main(args)
    elif args.format == "vba-ps" and args.template in [
        "default",
        "run",
        "exe",
        "dll",
    ]:
        powershell.main(args)
        vbapplication.main(args)
    else:
        list_options()
        quit()


@contextmanager
def temporarily_set_template(args, new_template):
    original_template = args.template
    args.template = new_template
    try:
        yield
    finally:
        args.template = original_template


if __name__ == "__main__":
    main()
