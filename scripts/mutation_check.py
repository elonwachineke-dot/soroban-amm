#!/usr/bin/env python3
"""Run curated, one-at-a-time guard mutations against a Rust crate's unit tests."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass


OPERATORS = ("auth", "error", "comparison")
PRIVILEGED_AUTH = (
    "admin",
    "current_admin",
    "new_admin",
    "governance",
    "keeper",
    "stored_admin",
)
ERROR_VARIANTS = (
    "DeadlineExceeded",
    "DeadlineExpired",
    "SlippageExceeded",
    "Unauthorized",
    "Paused",
    "ZeroAmount",
)
COMPARISON_FLIPS = {
    "<": ">=",
    "<=": ">",
    ">": "<=",
    ">=": "<",
    "==": "!=",
    "!=": "==",
}


@dataclass(frozen=True)
class Mutation:
    identifier: str
    operator: str
    line: int
    original: str
    mutated: str
    start: int
    end: int

    def apply(self, source):
        return source[: self.start] + self.mutated + source[self.end :]


@dataclass(frozen=True)
class Result:
    mutation: Mutation
    status: str


def production_source(source):
    """Keep mutations out of the conventional inline #[cfg(test)] module."""
    marker = re.search(r"(?m)^[ \t]*#\[cfg\(test\)\]", source)
    return source[: marker.start()] if marker else source


def _mutation(operator, source, start, end, mutated):
    original = source[start:end]
    line = source.count("\n", 0, start) + 1
    column = start - source.rfind("\n", 0, start)
    digest = hashlib.sha1(original.encode("utf-8")).hexdigest()[:8]
    return Mutation(
        identifier=f"{operator}:{line}:{column}:{digest}",
        operator=operator,
        line=line,
        original=original,
        mutated=mutated,
        start=start,
        end=end,
    )


def find_mutations(source, operators=OPERATORS):
    code = production_source(source)
    found = []

    if "auth" in operators:
        privileged_roles = "|".join(PRIVILEGED_AUTH)
        auth_pattern = re.compile(
            r"(?:"
            rf"\b(?:{privileged_roles})\s*\.\s*require_auth\s*\(\s*\)"
            r"|Self\s*::\s*get_keeper\s*\([^;\n]*?\)\s*\?\s*"
            r"\.\s*require_auth\s*\(\s*\)"
            r")\s*;"
        )
        for match in auth_pattern.finditer(code):
            found.append(_mutation("auth", code, match.start(), match.end(), ""))

    if "error" in operators:
        variants = "|".join(ERROR_VARIANTS)
        error_pattern = re.compile(
            rf"return\s+Err\s*\(\s*(?:[A-Za-z_]\w*::)?"
            rf"(?:{variants})\s*\)\s*;"
        )
        for match in error_pattern.finditer(code):
            found.append(_mutation("error", code, match.start(), match.end(), ""))

    if "comparison" in operators:
        comparison_pattern = re.compile(r"(?<![<>=!])(?:<=|>=|==|!=|<|>)(?![<>=])")
        offset = 0
        for line_number_text in code.splitlines(keepends=True):
            line = line_number_text.rstrip("\r\n")
            searchable = line.split("//", 1)[0]
            if re.search(r"deadline|min_|expires_at", searchable, re.IGNORECASE):
                for match in comparison_pattern.finditer(searchable):
                    start = offset + match.start()
                    end = offset + match.end()
                    found.append(
                        _mutation(
                            "comparison",
                            code,
                            start,
                            end,
                            COMPARISON_FLIPS[match.group()],
                        )
                    )
            offset += len(line_number_text)

    return sorted(found, key=lambda mutation: (mutation.line, mutation.start, mutation.operator))


def _atomic_write(path, content, mode):
    path = Path(path)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(content)
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def load_accepted_survivors(config_path, crate):
    with open(config_path, "rb") as stream:
        config = tomllib.load(stream)
    crate_config = config.get("crates", {}).get(crate, {})
    accepted = {}
    for entry in crate_config.get("accepted_survivors", []):
        identifier = entry["id"]
        justification = entry["justification"].strip()
        if not justification:
            raise ValueError(f"{crate}: accepted survivor {identifier!r} has no justification")
        accepted[identifier] = justification
    return accepted


class MutationCheck:
    def __init__(
        self,
        root,
        crate,
        timeout=300,
        operators=OPERATORS,
        accepted=None,
        command_runner=subprocess.run,
    ):
        self.root = Path(root)
        self.crate = crate
        self.timeout = timeout
        self.operators = tuple(operators)
        self.accepted = accepted or {}
        self.command_runner = command_runner
        self.source_path = self.root / "contracts" / crate / "src" / "lib.rs"

    def run(self):
        original_bytes = self.source_path.read_bytes()
        original_source = original_bytes.decode("utf-8")
        source_stat = self.source_path.stat()
        mutations = find_mutations(original_source, self.operators)
        results = []

        for mutation in mutations:
            mutated_source = mutation.apply(original_source)
            try:
                _atomic_write(
                    self.source_path,
                    mutated_source.encode("utf-8"),
                    source_stat.st_mode,
                )
                try:
                    completed = self.command_runner(
                        ["cargo", "test", "-p", self.crate, "--lib"],
                        cwd=self.root,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    status = "timed out"
                else:
                    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
                    if completed.returncode == 0:
                        status = "survived"
                    elif re.search(r"error\[E\d+\]:|could not compile", output, re.IGNORECASE):
                        status = "skipped (compile error)"
                    elif re.search(r"test result: FAILED|^test .+ \.\.\. FAILED$", output, re.MULTILINE):
                        status = "killed"
                    else:
                        raise RuntimeError(
                            "cargo test failed without reporting a compile error or failed test"
                        )
            finally:
                _atomic_write(self.source_path, original_bytes, source_stat.st_mode)
            results.append(Result(mutation, status))
        return results


def format_report(crate, results, accepted):
    lines = [f"Mutation check: {crate}"]
    counts = {
        "killed": 0,
        "survived": 0,
        "timed out": 0,
        "skipped (compile error)": 0,
    }
    unaccepted = []
    for result in results:
        counts[result.status] += 1
        if result.status in ("survived", "timed out"):
            mutation = result.mutation
            if result.mutation.identifier in accepted:
                lines.append(
                    f"ACCEPTED {result.status}: contracts/{crate}/src/lib.rs:"
                    f"{mutation.line} [{mutation.operator}; id={mutation.identifier}] "
                    f"({accepted[result.mutation.identifier]})"
                )
            else:
                unaccepted.append(result)
                lines.append(
                    f"UNACCEPTED {result.status}: contracts/{crate}/src/lib.rs:"
                    f"{mutation.line} [{mutation.operator}; id={mutation.identifier}]"
                )
            lines.append(f"  original: {mutation.original.strip()}")
            lines.append(f"  mutated:  {mutation.mutated.strip() or '(removed)'}")

    lines.append(
        "Summary: "
        + ", ".join(
            f"{status}={count}"
            for status, count in counts.items()
        )
    )
    lines.append(f"Unaccepted survivors: {len(unaccepted)}")
    return "\n".join(lines) + "\n", len(unaccepted)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crate", required=True, help="Cargo package name under contracts/")
    parser.add_argument(
        "--operators",
        nargs="+",
        choices=OPERATORS,
        default=list(OPERATORS),
        help="mutation operators to run (default: all)",
    )
    parser.add_argument("--timeout", type=int, default=300, help="test timeout in seconds")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "mutations.toml",
        help="accepted-survivor TOML file",
    )
    parser.add_argument("--report", type=Path, help="write the text report to this file")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.timeout <= 0:
        print("ERROR: --timeout must be positive", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parent.parent
    source_path = root / "contracts" / args.crate / "src" / "lib.rs"
    if not source_path.is_file():
        print(f"ERROR: crate source not found: {source_path}", file=sys.stderr)
        return 2

    try:
        accepted = load_accepted_survivors(args.config, args.crate)
        results = MutationCheck(
            root,
            args.crate,
            timeout=args.timeout,
            operators=args.operators,
            accepted=accepted,
        ).run()
        report, unaccepted_count = format_report(args.crate, results, accepted)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(report, encoding="utf-8")
        print(report, end="")
        return 1 if unaccepted_count else 0
    except KeyboardInterrupt:
        print("Mutation check interrupted; original source restored.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
