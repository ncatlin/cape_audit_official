# cape_audit
A python module for writing CAPEv2 sandbox test evaluators. 

This is designed to be used by developers to write tests for
* Guests and their environment (eg: Is traffic being redirected? Is AV destroying payloads?)
* CAPE deployment (Is the agent installed correctly, the sandbox configuration, the installed python modules) 
* CAPE behaviour (Does each module work, are the processors reporting the results correctly)
* Capemon behaviour (Stealth effectiveness, malware technique detection, API hooking support) 

By using a minimal, known and benign payload with a pre-defined CAPE task configuration, we can narrow down issues to the sandbox or its configuration.

The module (which needs to be installed in CAPE's python env) is used by the CAPE sandbox server in two situations:
* To extract test metadata when loading a test
* To evaluate test results after a task

## Usage Example

### Prepare

We need the module installed. Clone this repo and run something like:

```
python -m venv venv

.\venv\Scripts\Activate.ps1

# This is best for development so changes in 'cape_audit' reflect immediately
python -m pip install .\cape_audit
```

### Test Development

First we create the metadata describing the test and how CAPE will execute it

```python
from typing import Any, Dict, List, Optional, Union
from cape_audit.cape_audit import CapeDynamicTestBase, CapeTestObjective, OSTarget
from cape_audit.verifiers import VerifyReportSectionHasMatching, VerifyReportSectionHasContent

class CapeDynamicTest(CapeDynamicTestBase):
    def __init__(self):
        # only the test name and analysis package is mandatory
        super().__init__(test_name="api_tracing_1", analysis_package="exe")

        # set some messages for the user
        self.set_description("Tests API monitoring. " \
            "Runs a series of Windows API calls including file, registry, network and synchronisation.")
        self.set_payload_notes("A single statically linked 64-bit PE binary, tested on Windows 10.")
        self.set_result_notes("These simple hooking tests are all expected to succeed on a correct CAPE setup")

        # optional config fields
        self.set_zip_password(None)
        self.set_task_timeout_seconds(120)
        self.set_os_targets([OSTarget.WINDOWS])
        self.set_enforce_timeout(False)
        self.set_task_config({
              "Route": None,
              "Tags": [ "windows","x64"],
              "Request Options": "",
              "Custom Request Params": None
          })

        # init the test metadata
        self._init_objectives()
```

Now we describe the test objectives. These can be linear, or nested - so if one fails then all of its descendants will be skipped.

```python
    def _init_objectives(self):
        #
        # Objective 1: the first and only top-level objective in this test
        #
        
        # It's good to have a smoke test to ensure the environment is functional before testing it.
        # Check if there are any behavioural listings at all in the report
        o_has_behaviour_trace = CapeTestObjective(test=self,
                                                  requirement="API calls are being hooked",
                                                  objective_name="BehaviourInfoGenerated")

        # message for the web UI upon success
        o_has_behaviour_trace.set_success_msg("API hooking is working")

        # message for the web UI upon failure. If you know reasons this might fail
        # then this is the place to write suggestions.
        o_has_behaviour_trace.set_failure_msg("The sample failed to execute, the monitor failed\
                                         to initialise or API hooking is not working")

        # Now add a verifier for the objective. This is an object that returns a state, 
        # message and a dictionary of child states/messages.
        # You can roll your own for elaborate checks, but some standard ones are provided.
        # This evaluator simply checks that report.json has a certain key with content
        o_has_behaviour_trace.set_result_verifier(VerifyReportSectionHasContent("behavior"))

        # Now add this objective to the test as a top level objective
        self.add_objective(o_has_behaviour_trace)

        #
        # Objective 2: a child objective showing a finer-grained report.json parse
        #

        # Check if it caught the sleep API with a specific argument
        o_sleep_hook = CapeTestObjective(test=self, objective_name="DetectSleepTime",
                                         requirement="A sleep call is hooked, including its parameter",
                                         is_informational=False)
        o_sleep_hook.set_success_msg("CAPE hooked a sleep and retrieved the correct argument")
        o_sleep_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        # This evaluator checks if the calls list inside the process report has 
        # a sleep call that with parameter 1337
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "NtDelayExecution"}, 
                {"arguments/value": "1337"}
            ])
        o_sleep_hook.set_result_verifier(evaluator)
        # we add it as a child of the 'has behaviour' objective
        o_has_behaviour_trace.add_child_objective(o_sleep_hook)
```

You will also need a payload to test:

```
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int main() {

	// Test 1: Can it get the argument of a sleep call
	Sleep(1337);

	return 0;
}
```
These should ideally be statically linked (compiled with /MT) to reduce dependencies that might stop the test executing.

You can develop and test your 'test' locally by tasking the payload with the desired config and fetching the CAPE task storage directory.

```
if __name__ == "__main__":
    mytest = CapeDynamicTest()
    # developers: change me
    mytest.evaluate_results(r"[path_to_task_store_dir_after_payload_analysis]")
    # helper function to see how the result will be evaluted in reality
    mytest.print_test_results()
```

Now 
* Build the test project
* Upload the directory to CAPE (eg: /opt/CAPEv2/tests/audit/packages/api/api_tracing_1/test.py and payload.zip)
* Ensure the cape user has read and write permissions to it
* Reload tests in http[s]://your-cape-server/audit
* Create an audit session using the test
* Execute the test and evaluate the results

 <img width="1059" height="504" alt="Image" src="https://github.com/user-attachments/assets/bd3dedec-4230-4c43-8a4e-26c7a8a85cb0" />

See https://github.com/CAPESandbox/cape_dynamic_tests for template test projects