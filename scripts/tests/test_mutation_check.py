"""Fixture-only tests for scripts/mutation_check.py; no Cargo invocation."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.mutation_check import (
    MutationCheck,
    Result,
    find_mutations,
    format_report,
    load_accepted_survivors,
)


class MutationDiscoveryTests(unittest.TestCase):
    def test_discovers_privileged_auth_calls(self):
        source = "admin.require_auth();\ncurrent_admin.require_auth();\n"
        mutations = find_mutations(source, ("auth",))
        self.assertEqual(len(mutations), 2)
        self.assertTrue(all(item.operator == "auth" for item in mutations))

    def test_discovers_keeper_auth_call(self):
        mutations = find_mutations("Self::get_keeper(env)?.require_auth();\n", ("auth",))
        self.assertEqual(len(mutations), 1)

    def test_ignores_user_level_auth(self):
        mutations = find_mutations("caller.require_auth();\nfrom.require_auth();\n", ("auth",))
        self.assertEqual(mutations, [])

    def test_discovers_supported_guard_errors(self):
        source = (
            "return Err(AmmError::DeadlineExceeded);\n"
            "return Err(Error::SlippageExceeded);\n"
            "return Err(Unauthorized);\n"
        )
        self.assertEqual(len(find_mutations(source, ("error",))), 3)

    def test_ignores_unlisted_error_variants(self):
        mutations = find_mutations("return Err(AmmError::NotFound);\n", ("error",))
        self.assertEqual(mutations, [])

    def test_flips_comparison_operators_on_guard_lines(self):
        source = "if deadline < now && min_out >= amount { return Err(E); }\n"
        mutations = find_mutations(source, ("comparison",))
        self.assertEqual([item.mutated for item in mutations], [">=", "<"])
        self.assertTrue(all(item.line == 1 for item in mutations))

    def test_comparison_mutation_is_one_operator_at_a_time(self):
        source = "if expires_at == now { }\n"
        mutations = find_mutations(source, ("comparison",))
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0].mutated, "!=")

    def test_ignores_comparisons_outside_guard_lines(self):
        self.assertEqual(
            find_mutations("if balance < amount { }\n", ("comparison",)),
            [],
        )

    def test_excludes_inline_test_module(self):
        source = (
            "admin.require_auth();\n"
            "#[cfg(test)]\nmod tests { admin.require_auth(); }\n"
        )
        mutations = find_mutations(source, ("auth",))
        self.assertEqual(len(mutations), 1)


class MutationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.source_path = self.root / "contracts" / "fixture" / "src" / "lib.rs"
        self.source_path.parent.mkdir(parents=True)
        self.original = "pub fn guard() { admin.require_auth(); }\n"
        self.source_path.write_text(self.original, encoding="utf-8")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def checker(self, command_runner):
        return MutationCheck(
            self.root,
            "fixture",
            operators=("auth",),
            command_runner=command_runner,
        )

    def assert_restored(self):
        self.assertEqual(self.source_path.read_text(encoding="utf-8"), self.original)

    def test_restores_source_after_killed_mutant(self):
        result = self.checker(
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args[0], 1, "test result: FAILED. 0 passed; 1 failed", ""
            )
        ).run()
        self.assertEqual(result[0].status, "killed")
        self.assert_restored()

    def test_restores_source_after_surviving_mutant(self):
        result = self.checker(
            lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", "")
        ).run()
        self.assertEqual(result[0].status, "survived")
        self.assert_restored()

    def test_restores_source_after_timeout(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

        result = self.checker(timeout).run()
        self.assertEqual(result[0].status, "timed out")
        self.assert_restored()

    def test_restores_source_after_keyboard_interrupt(self):
        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.checker(interrupt).run()
        self.assert_restored()

    def test_skips_compile_error_and_restores_source(self):
        result = self.checker(
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args[0], 1, "", "error[E0308]: mismatched types"
            )
        ).run()
        self.assertEqual(result[0].status, "skipped (compile error)")
        self.assert_restored()

    def test_unclassified_command_failure_surfaces_and_restores_source(self):
        command = lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, "", "failed to download dependency"
        )
        with self.assertRaisesRegex(RuntimeError, "without reporting"):
            self.checker(command).run()
        self.assert_restored()

    def test_runs_cargo_for_the_requested_package(self):
        observed = []

        def fake_cargo(command, **kwargs):
            observed.append(command)
            return subprocess.CompletedProcess(
                command, 1, "test result: FAILED. 0 passed; 1 failed", ""
            )

        self.checker(fake_cargo).run()
        self.assertEqual(observed, [["cargo", "test", "-p", "fixture", "--lib"]])


class SurvivorRatchetTests(unittest.TestCase):
    def test_accepted_survivor_is_reported_but_not_unaccepted(self):
        source = "admin.require_auth();\n"
        mutation = find_mutations(source, ("auth",))[0]
        report, unaccepted = format_report(
            "fixture",
            [Result(mutation, "survived")],
            {mutation.identifier: "fixture exemption"},
        )
        self.assertEqual(unaccepted, 0)
        self.assertIn("ACCEPTED survived", report)

    def test_unlisted_survivor_prints_location_and_text(self):
        source = "admin.require_auth();\n"
        mutation = find_mutations(source, ("auth",))[0]
        report, unaccepted = format_report("fixture", [Result(mutation, "survived")], {})
        self.assertEqual(unaccepted, 1)
        self.assertIn("contracts/fixture/src/lib.rs:1 [auth;", report)
        self.assertIn("original: admin.require_auth();", report)
        self.assertIn("mutated:  (removed)", report)

    def test_loads_accepted_survivor_justification(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "mutations.toml"
            config.write_text(
                '[crates.fixture]\n'
                'accepted_survivors = [{ id = "auth:1:1:abc12345", '
                'justification = "known nested authorization" }]\n',
                encoding="utf-8",
            )
            self.assertEqual(
                load_accepted_survivors(config, "fixture"),
                {"auth:1:1:abc12345": "known nested authorization"},
            )

    def test_empty_accepted_list_has_no_exemptions(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "mutations.toml"
            config.write_text("[crates.fixture]\naccepted_survivors = []\n", encoding="utf-8")
            self.assertEqual(load_accepted_survivors(config, "fixture"), {})


if __name__ == "__main__":
    unittest.main()
