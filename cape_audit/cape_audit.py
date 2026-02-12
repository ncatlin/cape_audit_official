
from __future__ import annotations
from typing import List, Union, Dict, Any
import json
import logging
import os
from enum import Enum
from .verifiers import MissingResultVerifier

class OSTarget(str, Enum):
    WINDOWS = "windows"
    LINUX   = "linux"
    MACOS   = "macos"
    ANDROID   = "android"
    IOS   = "ios"

    # This allows: str(OSTarget.WINDOWS) -> "windows"
    def __str__(self):
        return self.value
 
class ObjectiveResult(str, Enum):
    '''Default state, the objective hasn't been checked yet'''
    UNTESTED = "untested"
    '''The objective was met by the test. Child objectives will be evaluated.'''
    SUCCESS = "success"
    '''The objective was not achieved during the test. Child objectives will be skipped.''' 
    FAILURE   = "failure"
    '''An error occoured while verifying this objective. Child objectives will be skipped.'''
    ERROR   = "error"
    '''The test produced useful information about this objective 
    that is neither good nor bad. Child objectives will be evaluated'''
    INFO   = "info"
    '''The objective was ignored because a parent objective
        failed or was skipped'''
    SKIPPED = "skipped"

    # This allows: str(OSTarget.WINDOWS) -> "windows"
    def __str__(self):
        return self.value

class CapeTestObjective:
    def __init__(self, objective_name :str, requirement :str, test, is_informational=False):
        self.name = objective_name
        self.children = []
        self.state = ObjectiveResult.UNTESTED
        self.state_reason = "Objective has not been tested yet"
        self.test = test
        self.result_verifier = MissingResultVerifier()
        self._is_informational = is_informational
        self.requirement = requirement
        self._success_msg = "set_success_msg() was not called when creating the objective"
        self._failure_msg = "set_failure_msg() was not called when creating the objective"
        self.report = {'error':'report not initialised'}
        self.report_string = "error: report string not initialised"
        self.storage_path = "error: storage path not initialised"

    def get_requirement(self): 
        return self.requirement

    def get_name(self): 
        return self.name

    def get_children(self): 
        return self.children

    def set_success_msg(self, msg: str):
        self._success_msg = msg

    def set_failure_msg(self, msg: str):
        self._failure_msg = msg

    def set_test_data(self, report: dict, report_string: str, storage_path: str):
        self.report = report
        self.report_string = report_string
        self.storage_path = storage_path

    def set_result_verifier(self, evaluator_object):
        if not hasattr(evaluator_object, "evaluate"):
            raise Exception("Verifier has no evaluate method")
        self.result_verifier = evaluator_object

    def run_objective_verification(self):
        try:
            result = self.result_verifier.evaluate(self.report, self.report_string, self.storage_path)
            self.state_reason = self._success_msg if result else self._failure_msg
            if self._is_informational:
                self.state = ObjectiveResult.INFO
            else:
                self.state = ObjectiveResult.SUCCESS if result else ObjectiveResult.FAILURE
        except Exception as e:
            self.state = ObjectiveResult.ERROR
            self.state_reason = f"An exception was thrown during verification: {str(e)}"
            log = logging.getLogger(__name__)
            log.exception("An exception was thrown during verification of test %s:%s",self.test.name, self.name)
            
        if self.state in [ObjectiveResult.SUCCESS, ObjectiveResult.INFO]:
            for child in self.children:
                child.set_test_data(self.report, self.report_string, self.storage_path)
                child.run_objective_verification()
        else:
            for child in self.children:
                child.set_skipped("The parent objective was not met")

    def set_skipped(self, reason):
        self.state = ObjectiveResult.SKIPPED
        self.state_reason = reason
        for child in self.children:
            child.set_skipped(reason)

    def add_child_objective(self, objective: CapeTestObjective):
        ''' Add another objective which is evaluated if
        this objective is evaluated and does not fail '''
        if objective.name in {d.name for d in self.children}:
            raise ValueError(f"Objective {self.name} already has a child objective called {objective.name}")
        objective.set_test_data(self.report, self.report_string, self.storage_path)
        self.children.append(objective)

    def get_results(self):
        result = {
            'state':self.state, 
            'state_reason': self.state_reason,
            'children': {}
            }      
        for child in self.children:
            result['children'][child.name] = child.get_results()
        return result
        

class CapeDynamicTestBase:
    def __init__(self, test_name, analysis_package):
        self._metadata = {"Name": test_name, "Package":analysis_package}
        self._objectives = []
        self.name = test_name
        self.package = analysis_package
        self.set_task_timeout_seconds(120)
        self.set_description("No description set for this test")
        self.set_zip_password(None)
        self.set_payload_notes(None)
        self.set_result_notes(None)
        self.set_enforce_timeout(False)
        self.set_os_targets([])
        self.set_task_config({})
    
    def init_metadata(self, metadata: dict):
        ''' Set metadata from a dict (eg: matching the format from get_metadata()) 
        instead of setting each field individually'''
        metadata['Name'] = self.name
        metadata['Package'] = self.package
        self._metadata = metadata

    def get_metadata(self) -> dict:
        return self._metadata
    
    def get_objectives(self):
        return self._objectives
    
    def evaluate_results(self, test_storage_directory: str) -> Dict:
        '''
        Performs objective evaluation using the storage path of the executed
        task. Results available from get_results()

        :param test_storage_directory: The CAPE storage directory for this test containing analysis.log
        '''
        if not os.path.exists(test_storage_directory):
            raise FileNotFoundError(f"Test storage dir {test_storage_directory} not found ")
        if not os.path.isdir(test_storage_directory):
            raise IsADirectoryError(f"Test storage dir {test_storage_directory} not a directory")
        reportpath = os.path.join(test_storage_directory, "reports", "report.json")
        
        if not os.path.exists(reportpath):
            raise FileNotFoundError(f"Test evaluation requires a report at {reportpath}")

        with open(reportpath) as f:
            self.report_string = f.read()
        self.report = json.loads(self.report_string)
        self.test_storage_directory= test_storage_directory
        self._run_objective_verification()
        return self.get_results()

    def _run_objective_verification(self):
        for objective in self._objectives:
            objective.set_test_data(self.report, self.report_string, self.test_storage_directory)
            objective.run_objective_verification()
       
    def get_results(self) -> Dict:
        '''
        Get a nested dictionary of evaluated objective results
        '''
        results = {}
        for objective in self._objectives:
            results[objective.name] = objective.get_results()
        return results
       
    def set_description(self, test_description: str) -> None:
        self._metadata["Description"] = test_description
        
    def set_payload_notes(self, payload_notes:  None | str) -> None:
        self._metadata["Payload Notes"] = payload_notes
        
    def set_result_notes(self, result_notes:  None | str) -> None:
        self._metadata["Result Notes"] = result_notes
        
    def set_zip_password(self, password: None | str) -> None:
        self._metadata["Zip Password"] = password
        
    def set_task_timeout_seconds(self, analysis_timeout: int) -> None:
        try:
            self._metadata["Timeout"] = int(analysis_timeout)
        except ValueError:
            raise ValueError("Bad Timeout Value - Must be a valid integer")

    def set_enforce_timeout(self, val: bool) -> None:
        if not isinstance(val, bool):
            raise ValueError("Bad Enforce Timeout Value - Must be True/False")
        self._metadata["Enforce Timeout"] = val

    def set_os_targets(self, targets: Union[OSTarget, List[OSTarget]]) -> None:
        if isinstance(targets, OSTarget):
            self._metadata["Targets"] = [str(targets)]
        else:
            self._metadata["Targets"] = [str(t) for t in targets]
        
    def set_task_config(self, task_config: Dict[str, Any]) -> None:
        try:
            json.dumps(task_config)
            if task_config.get("Request Options",None) is None:
                task_config = ""
            self._metadata["Task Config"] = task_config
        except TypeError:
            raise Exception("Bad config - must be json serializable")
    
    def add_objective(self, objective: CapeTestObjective):
        '''
        Add a top-level objective to the test
        '''
        # This permits duplicate objective names within different levels of the tree
        # Internally we will concat the names so they are still unique
        if objective.name in {d.name for d in self._objectives}:
            raise ValueError(f"Test already has an Objective called {objective.name}")
        self._objectives.append(objective)

    def _print_objective_results(self, name, objinfo, indent = 0):
        print(f"{indent*' '}{name}: {objinfo['state']} ({objinfo['state_reason']})")
        for cname,cinfo in objinfo['children'].items():
            self._print_objective_results(cname, cinfo, indent=indent+4)

    def print_test_results(self):
        '''
        Developer helper function for printing test results to the console
        '''
        results = self.get_results()
        for obj,res in results.items():
            self._print_objective_results(obj, res, indent = 0)
