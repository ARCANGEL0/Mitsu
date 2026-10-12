import asyncio
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from mitsu.search.vulnerabilities import search_vulnx, search_vulnerabilities, vulnerability_queries
from mitsu.tools.agent_host import AgentToolHost


class VulnerabilitySearchTests(unittest.TestCase):
    def setUp(self):
        self.intel = {
            "assets": [
                {
                    "type": "technology",
                    "value": "OpenAM",
                    "attributes": {
                        "product": "OpenAM",
                        "version": "16.0.5",
                        "banner": "token=do-not-search-this",
                    },
                    "evidence": [{"details": "password=do-not-search-this"}],
                },
                {"type": "ip", "value": "10.129.164.25", "attributes": {}},
            ],
            "observations": [
                {
                    "title": "OpenAM 16.0.5 on 4444",
                    "details": "token=do-not-search-this",
                }
            ],
            "findings": [{"title": "CVE-2026-33439 candidate"}],
            "exploits": [],
        }

    def test_builds_small_queries_from_product_intel(self):
        queries = vulnerability_queries("", self.intel)

        self.assertIn("OpenAM 16.0.5", queries)
        self.assertIn("OpenAM 16.0.5 CVE vulnerability", queries)
        self.assertIn("CVE-2026-33439 candidate", queries)
        self.assertLessEqual(len(queries), 4)
        self.assertNotIn("10.129.164.25", queries)
        self.assertNotIn("do-not-search-this", " ".join(queries))

    def test_openam_lead_joins_web_and_local_references(self):
        web_queries = []
        local_queries = []
        vulnx_queries = []

        def web_search(query, count, configured):
            web_queries.append(query)
            if "CVE vulnerability" in query:
                return "OpenAM advisory · CVE-2026-33439 · affected versions include 16.0.5"
            return "No matching advisory."

        def local_search(query):
            local_queries.append(query)
            if "OpenAM" in query:
                return ([{"title": "OpenAM remote code execution", "id": "12345", "path": "exploits/linux/remote/12345.py"}], None)
            return ([], None)

        def vulnx_search(query):
            vulnx_queries.append(query)
            return ("CVE-2026-33439 · OpenAM 16.0.5", None)

        result = search_vulnerabilities(
            "",
            self.intel,
            {"exa": {"enabled": True}},
            web_searcher=web_search,
            local_searcher=local_search,
            vulnx_searcher=vulnx_search,
        )

        self.assertIn("CVE-2026-33439", result)
        self.assertIn("EDB-12345", result)
        self.assertIn("VULNX REFERENCES", result)
        self.assertIn("CVE-2026-33439 · OpenAM 16.0.5", result)
        self.assertIn("unverified references", result)
        self.assertTrue(any("OpenAM 16.0.5" in query for query in web_queries))
        self.assertEqual(set(web_queries), set(local_queries))
        self.assertLessEqual(len(vulnx_queries), 2)
        self.assertNotIn("do-not-search-this", " ".join(web_queries))

    def test_rejects_option_like_criteria_before_searching(self):
        called = []
        result = search_vulnerabilities(
            "--exec",
            self.intel,
            {},
            web_searcher=lambda *args: called.append(args) or "",
            local_searcher=lambda query: called.append(query) or ([], None),
        )

        self.assertIn("Use product, version, CVE", result)
        self.assertEqual(called, [])


class VulnerabilityIntelTests(unittest.TestCase):
    def test_loads_saved_product_version_for_a_search(self):
        async def ask_user(question, choices):
            return ""

        async def update_intel(action, values):
            if values["section"] == "summary":
                return json.dumps(
                    {
                        "asset_count": 1,
                        "observation_count": 0,
                        "finding_count": 0,
                        "exploit_count": 0,
                    }
                )
            records = (
                [{"type": "technology", "value": "OpenAM", "attributes": {"version": "16.0.5"}}]
                if values["section"] == "assets"
                else []
            )
            return json.dumps({"records": records})

        host = AgentToolHost(
            Path.cwd(),
            ask_user,
            update_intel,
            search_settings=lambda: {},
        )
        intel = asyncio.run(host._vulnerability_intel())

        self.assertEqual(intel["assets"][0]["value"], "OpenAM")
        self.assertIn("OpenAM 16.0.5", vulnerability_queries("", intel))


class VulnxCommandTests(unittest.TestCase):
    @patch("mitsu.search.vulnerabilities.subprocess.run")
    def test_search_uses_json_mode_and_keeps_query_as_one_argument(self, run):
        run.return_value = type(
            "Result", (), {"returncode": 0, "stdout": '{"results": []}', "stderr": ""}
        )()

        result, error = search_vulnx(
            "OpenAM 16.0.5 CVE vulnerability", "/opt/vulnx", ("--quiet",)
        )

        self.assertIsNone(error)
        self.assertIn('"results": []', result)
        self.assertEqual(
            run.call_args.args[0],
            [
                "/opt/vulnx",
                "--quiet",
                "search",
                "OpenAM 16.0.5 CVE vulnerability",
                "--limit",
                "8",
                "--json",
                "--silent",
            ],
        )

    def test_missing_search_tools_go_through_install_consent(self):
        async def ask_user(question, choices):
            return "No"

        host = AgentToolHost(Path.cwd(), ask_user, search_settings=lambda: {})
        host._install_armory_tool = AsyncMock(
            side_effect=[(False, "SearchSploit declined"), (False, "Vulnx declined")]
        )

        async def prepare():
            with patch("mitsu.tools.agent_host.resolve_executable", return_value=None):
                return await host._prepare_vulnsearch_backends(
                    "", {"assets": [{"type": "technology", "value": "OpenAM 16.0.5"}]}
                )

        local_searcher, local_status, vulnx_searcher, vulnx_status = asyncio.run(prepare())

        self.assertEqual(host._install_armory_tool.await_count, 2)
        self.assertEqual(
            [call.args[0] for call in host._install_armory_tool.await_args_list],
            ["exploitdb", "vulnx"],
        )
        self.assertIn("declined", local_status)
        self.assertIn("declined", vulnx_status)
        self.assertEqual(local_searcher("OpenAM"), ([], None))
        self.assertEqual(vulnx_searcher("OpenAM"), ("", None))


if __name__ == "__main__":
    unittest.main()
