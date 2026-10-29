"""python -m patchpilot <command>

  scan   Scan dependency manifests (folder, file or --repo URL); exit 0 clean, 1 findings, 2 error
  serve  Start the web server and API
  fix    Run the fix agent on repos / bundled cases (same as python -m patchpilot.cli)
"""
import sys

USAGE = __doc__.strip()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if argv else 2
    cmd, rest = argv[0], argv[1:]
    from patchpilot import cli
    if cmd == "scan":
        return cli.scan_main(rest)
    if cmd == "serve":
        return cli.serve_main(rest)
    if cmd == "fix":
        return cli.main(rest)
    print(f"patchpilot: unknown command '{cmd}'\n\n{USAGE}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
