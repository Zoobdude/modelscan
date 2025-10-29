import abc
import logging
import json
from typing import Optional, Dict, Any

from rich import print

from modelscan.modelscan import ModelScan
from modelscan.issues import IssueSeverity

logger = logging.getLogger("modelscan")


class Report(metaclass=abc.ABCMeta):
    """
    Abstract base class for different reporting modules.
    """

    def __init__(self) -> None:
        pass

    @staticmethod
    def generate(
        scan: ModelScan,
        settings: Dict[str, Any] = {},
    ) -> Optional[str]:
        """
        Generate report for the given codebase.
        Derived classes must provide implementation of this method.

        :param issues: Instance of Issues object

        :param errors: Any errors that occurred during the scan.
        """
        raise NotImplementedError


class ConsoleReport(Report):
    @staticmethod
    def generate(
        scan: ModelScan,
        settings: Dict[str, Any] = {},
    ) -> None:
        issues_by_severity = scan.issues.group_by_severity()
        print("\n[blue]--- Summary ---")
        total_issue_count = len(scan.issues.all_issues)
        if total_issue_count > 0:
            print(f"\nTotal Issues: {total_issue_count}")
            print("\nTotal Issues By Severity:\n")
            for severity in IssueSeverity:
                if severity.name in issues_by_severity:
                    print(
                        f"    - {severity.name}: {len(issues_by_severity[severity.name])}"
                    )
                else:
                    print(f"    - {severity.name}: [green]0")

            print("\n[blue]--- Issues by Severity ---")
            for issue_keys in issues_by_severity.keys():
                print(f"\n[blue]--- {issue_keys} ---")
                for issue in issues_by_severity[issue_keys]:
                    issue.print()
        else:
            print("\n[green] No issues found! 🎉")

        if len(scan.errors) > 0:
            print("\n[red]--- Errors --- ")
            for index, error in enumerate(scan.errors):
                print(f"\nError {index+1}:")
                print(str(error))

        if len(scan.skipped) > 0:
            print("\n[blue]--- Skipped --- ")
            print(
                f"\nTotal skipped: {len(scan.skipped)} - run with --show-skipped to see the full list."
            )
            if settings["show_skipped"]:
                print("\nSkipped files list:\n")
                for file_name in scan.skipped:
                    print(str(file_name))


class JSONReport(Report):
    @staticmethod
    def generate(
        scan: ModelScan,
        settings: Dict[str, Any] = {},
    ) -> None:
        report: Dict[str, Any] = scan._generate_results()
        if not settings.get("show_skipped"):
            del report["summary"]["skipped"]

        print(json.dumps(report))

        output = settings.get("output_file")
        if output:
            with open(output, "w") as outfile:
                json.dump(report, outfile)


class SARIFReport(Report):
    @staticmethod
    def generate(
        scan: ModelScan,
        settings: Dict[str, Any] = {},
    ) -> None:
        """
        Generate SARIF format report.
        SARIF (Static Analysis Results Interchange Format) is a standard format for
        static analysis tool output.
        """
        from modelscan._version import __version__

        results = scan._generate_results()

        # Map severity levels to SARIF levels
        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }

        # Build SARIF rules from issues
        rules = []
        rule_ids = set()

        # Use the JSON-formatted issues which have relative paths
        for issue in results.get("issues", []):
            rule_id = f"modelscan/{issue['operator']}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "name": f"Unsafe{issue['operator']}",
                        "shortDescription": {
                            "text": f"Use of unsafe operator '{issue['operator']}'"
                        },
                        "fullDescription": {
                            "text": f"Use of unsafe operator '{issue['operator']}' from module '{issue['module']}'"
                        },
                        "help": {
                            "text": f"The operator '{issue['operator']}' from module '{issue['module']}' can be used to execute arbitrary code and poses a security risk."
                        },
                        "defaultConfiguration": {
                            "level": severity_map.get(issue["severity"], "warning")
                        },
                        "properties": {
                            "tags": ["security", "model-scanning"],
                            "precision": "high",
                        },
                    }
                )

        # Build SARIF results from issues
        sarif_results = []
        for issue in results.get("issues", []):
            rule_id = f"modelscan/{issue['operator']}"
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": severity_map.get(issue["severity"], "warning"),
                    "message": {
                        "text": f"Use of unsafe operator '{issue['operator']}' from module '{issue['module']}'"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": issue["source"],
                                    "uriBaseId": "%SRCROOT%",
                                }
                            }
                        }
                    ],
                    "properties": {
                        "module": issue["module"],
                        "operator": issue["operator"],
                        "scanner": issue["scanner"],
                        "severity": issue["severity"],
                    },
                }
            )

        # Build the complete SARIF document
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ModelScan",
                            "version": __version__,
                            "informationUri": "https://github.com/protectai/modelscan",
                            "rules": rules,
                        }
                    },
                    "results": sarif_results,
                    "properties": {
                        "summary": {
                            "total_issues": results["summary"]["total_issues"],
                            "total_issues_by_severity": results["summary"][
                                "total_issues_by_severity"
                            ],
                            "total_scanned": results["summary"]["scanned"][
                                "total_scanned"
                            ],
                        }
                    },
                    "originalUriBaseIds": {
                        "%SRCROOT%": {"uri": results["summary"]["absolute_path"] + "/"}
                    },
                }
            ],
        }

        print(json.dumps(sarif_report, indent=2))

        output = settings.get("output_file")
        if output:
            with open(output, "w") as outfile:
                json.dump(sarif_report, outfile, indent=2)
