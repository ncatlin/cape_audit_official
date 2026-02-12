from typing import Dict, Any, List
import re
from pathlib import Path


class MissingResultVerifier:
    def evaluate(self, report: Dict[str, Any], report_string: str, test_storage_directory: str) -> bool:
        raise Exception("No verifier was attached to this objective")


class VerifyReportSectionHasContent:
    """
    Assert that the CAPE report.json contains a specific section
    """
    def __init__(
        self, 
        path: str
    ):
        self.path = path  # e.g., "behavior/processes/calls"
        
    def evaluate(self, report: Dict[str, Any], report_string: str, test_storage_directory: str) -> bool:
        innerVerifier = VerifyReportSectionHasMatching(self.path, [])
        return innerVerifier.has_content(report)


class VerifyReportSectionHasMatching:
    """
    Assert that the report.json contains matching prop:value pairs at a specific path
    Keyword arguments

    path -- the path in the json document eg: "behavior/processes/calls" searches for {"behaviour":{"processes":[{"calls":[...]}]}}
    match_criteria -- eg: [{ "api": "OutputDebugStringA"}, {"arguments/value": r"FLAG_1"}]
    values_are_regexes -- if true, matches the match_criteria as regular expressions. If false - exact string matches.
    """
    def __init__(
        self, 
        path: str, 
        match_criteria: List[Dict[str, Any]] | None,
        values_are_regexes: bool = False
    ):
        self.path = path  # e.g., "behavior/processes/calls"
        self.match_criteria = match_criteria
        self.is_regexes = values_are_regexes
        self.check_criteria_format()

    def check_criteria_format(self):
        if self.match_criteria is None:
            return

        if not isinstance(self.match_criteria, list):
            raise TypeError(f"match_criteria must be a list, got {type(self.match_criteria).__name__}")

        for criterion in self.match_criteria:
            if not isinstance(self.match_criteria, list):
                raise TypeError(f"match_criteria must be a list, got {type(self.match_criteria).__name__}")
            if len(criterion) != 1:
                raise ValueError(f"Invalid criteria: {criterion}. Expected exactly one key-value pair.")

    def has_content(self, report) -> bool:
        targets = self._resolve_path(report, self.path)
        if targets:
            return True
        else:
            return False

    def evaluate(self, report: Dict[str, Any], report_string: str, test_storage_directory: str) -> bool:
        """
        Returns True or False based on whether the criteria were met.

        Keyword arguments
        report -- report.json parsed as a dictionary
        report_string -- report.json as a raw string for direct searching
        test_storage_directory -- the path of the storage directory, for custom test evaluation
        """
        # 1. Resolve the path to get the list of items (processes or calls)
        targets = self._resolve_path(report, self.path)
        
        if not isinstance(targets, list):
            # If the result is a single dict, wrap it in a list so we can iterate
            targets = [targets] if targets else []

        if self.match_criteria is None:
            return True
        
        match_count_target = len(self.match_criteria) 
        for target in targets:
            match_count = 0
            for criterion in self.match_criteria:
                expected_path, expected_value = next(iter(criterion.items()))

                # For each criteria, resolve the path RELATIVE to the target
                found_vals = self._resolve_path(target, expected_path)
                
                # If resolve_path found the value (even inside a nested list)
                if self._verify_value(found_vals, expected_value):
                    match_count += 1
                    if match_count >= match_count_target:
                        return True
        return False

    def _resolve_path(self, data: Any, path: str) -> Any:
        """
        Recursively descends into data. 
        If it hits a list, it flattens the results from all items in that list.
        """
        keys = path.split('/')
        current = data

        for i, key in enumerate(keys):
            if isinstance(current, list):
                # List of dicts, so we have to check the path of every item
                remaining_path = "/".join(keys[i:])
                results = []
                for item in current:
                    res = self._resolve_path(item, remaining_path)
                    if isinstance(res, list):
                        results.extend(res)
                    elif res is not None:
                        results.append(res)
                return results
            
            if not isinstance(current, dict):
                return None
            current = current.get(key)

        return current

    def _verify_value(self, found: Any, expected: Any) -> bool:
        """Checks if expected value exists in found (handles single values or lists)"""

        found_list = found if isinstance(found, list) else [found]
        if self.is_regexes:
            pattern = re.compile(expected)
            return any(pattern.search(str(v)) for v in found_list)
        
        if isinstance(found, list):
            return any(str(v) == str(expected) for v in found)
        return str(found) == str(expected)
    

class VerifyReportHasExactString:
    """
    evaluate returns true if the raw text of report.json contains a specific string
    """
    def __init__(
        self, 
        pattern: str
    ):
        self.pattern = pattern
        
    def evaluate(self, report: Dict[str, Any], report_string: str, test_storage_directory: str) -> bool:
        """
        Returns True or False based on whether the criteria were met.

        Keyword arguments
        report -- report.json parsed as a dictionary
        report_string -- report.json as a raw string for direct searching
        test_storage_directory -- the path of the storage directory, for custom test evaluation
        """
        return self.pattern in report_string

class VerifyReportHasPattern:
    """
    evaluate returns true if the raw text of report.json matches the provided regex
    """
    def __init__(
        self, 
        pattern: re.Pattern
    ):
        self.pattern = pattern  # e.g., "behavior/processes/calls"
        
    def evaluate(self, report: Dict[str, Any], report_string: str, test_storage_directory: str) -> bool:
        """
        Returns True or False based on whether the criteria were met.

        Keyword arguments
        report -- report.json parsed as a dictionary
        report_string -- report.json as a raw string for direct searching
        test_storage_directory -- the path of the storage directory, for custom test evaluation
        """
        return self.pattern.search(report_string) is not None


class VerifyFileContainsPattern:
    """
    evaluate returns true if the file matches the provided regex
    Keyword arguments
    storage_relative_path -- file in the storage directory eg: 'analysis.log', 'tlsdump/tlsdump.log'
    pattern -- regex to match
    binary_mode -- True if the expected file and pattern is bytes instead of text
    """
    def __init__(
        self, 
        storage_relative_path: str,
        pattern: re.Pattern,
        binary_mode: bool = False
    ):
        self.pattern = pattern  # e.g., "behavior/processes/calls"
        self.relative_path = storage_relative_path
        self.binary_mode = binary_mode
        
    def evaluate(self, report: Dict[str, Any], report_string: str, test_storage_directory: str) -> bool:
        base_dir = Path(test_storage_directory).resolve()
        file_path = (base_dir / self.relative_path).resolve()
        
        try:
            file_path.relative_to(base_dir)
        except ValueError:
            raise ValueError("Non-relative path supplied to VerifyFileContainsPattern: "+self.relative_path)

        if not file_path.exists():
            return False

        if not file_path.is_file():
            return False

        mode = 'rb' if self.binary_mode else 'r'
        with file_path.open(mode) as f:
            data = f.read()
        
        return bool(self.pattern.search(data))
