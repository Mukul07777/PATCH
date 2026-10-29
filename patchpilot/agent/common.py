"""Constants and helpers shared by the agent modules."""
import re

PIN = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-]+)\s*$")
TEXT_EXT = {".py", ".txt", ".toml", ".cfg", ".ini", ".md"}
# lives in a dot-dir: the normal pytest run skips it and the diff ignores it
EXPLOIT_TEST = ".patchpilot/test_exploit.py"
MUTATION_TEST = ".patchpilot/test_mutations.py"


def extract_test_code(text):
    """Pull a compilable pytest file out of a reply (content or leaked reasoning); None if there isn't one."""
    blocks = re.findall(r"```(?:python|py)?[ \t]*\n(.*?)```", text or "", re.S)
    if not blocks and "def test" in (text or ""):
        blocks = [text]
    for code in sorted(blocks, key=len, reverse=True):
        code = code.strip()
        if not re.search(r"^def test\w*\(", code, re.M):
            continue
        try:
            compile(code, "test_exploit.py", "exec")
        except SyntaxError:
            continue
        return code + "\n"
    return None
