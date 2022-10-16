########################################################################
# File :   Originally ARCComputingElement.py
# Author : Raja Nandakumar
# Use the ARC REST interface and retire api libraries when complete
########################################################################

""" AREX Computing Element (ARC REST interface)
    Using the REST interface now and fail if REST interface is not available.
    A lot of the features are common with the API interface. In particular, the XRSL
    language is used in both cases. So, we retain the xrslExtraString and xrslMPExtraString strings.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

__RCSID__ = "$Id$"

import six
import os
import stat
import sys

import requests
import json
import ldap3

# from urllib.parse import urljoin

from DIRAC import S_OK, S_ERROR, gConfig
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getCESiteMapping
from DIRAC.Core.Utilities.Subprocess import shellCall
from DIRAC.Core.Utilities.File import makeGuid
from DIRAC.Core.Utilities.List import breakListIntoChunks
from DIRAC.Core.Security.ProxyInfo import getVOfromProxyGroup
from DIRAC.Resources.Computing.ARCComputingElement import ARCComputingElement
from DIRAC.Core.Security.ProxyInfo import getProxyInfo
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.Core.Security import Locations
from DIRAC.Core.Utilities.ReturnValues import returnValueOrRaise
from DIRAC.ConfigurationSystem.Client.Helpers.Path import cfgPath

CE_NAME = "AREX"
MANDATORY_PARAMETERS = ["Queue"]  # Mandatory for ARC CEs

# Note : interiting from ARCComputingElement. See https://github.com/DIRACGrid/DIRAC/pull/5330#discussion_r740907255
class AREXComputingElement(ARCComputingElement):

    # Used in getJobStatus
    mapStates = {
        "Accepted": "Scheduled",
        "Preparing": "Scheduled",
        "Submitting": "Scheduled",
        "Queuing": "Scheduled",
        "Undefined": "Unknown",
        "Running": "Running",
        "Finishing": "Running",
        "Deleted": "Killed",
        "Killed": "Killed",
        "Failed": "Failed",
        "Hold": "Failed",
        "Finished": "Done",
        "Done": "Done",
        "Other": "Done",
    }

    #############################################################################
    def __init__(self, ceUniqueID):
        """Standard constructor."""
        super(AREXComputingElement, self).__init__(ceUniqueID)
        self.ceType = CE_NAME
        self.submittedJobs = 0
        self.mandatoryParameters = MANDATORY_PARAMETERS
        self.pilotProxy = ""
        self.queue = ""
        self.outputURL = "gsiftp://localhost"
        self.ceHost = self.ceName

        result = returnValueOrRaise(getCESiteMapping(self.ceHost))
        self.site = result[self.ceHost]
        self.grid = self.site.split(".")[0]

    #############################################################################
    @property
    def initialised(self):
        """Check if the REST interface is available and ready, configuring it if required.
        Hopefully this is executed just once per CE, though it should not harm to run it more often.
        If all is well the following variables are set, and a few others on which they (especially self.s) depend.
        self.initialised : Static variable to say if the REST interface is available and ready
        self.base_url: The basic URL for the REST interface
        self.s       : The python "requests" module session
        self.headers : The format of information we prefer : json of course
        Specification : https://www.nordugrid.org/arc/arc6/tech/rest/rest.html

        The following needed variables are obtained from the CS. If not available, some hopefully
        sensible defaults are set.
        "RESTEndpoint"      - CE is Queried if not available in CS
               - The endpoint we talk to
        "XRSLExtraString" - Default = ""
               - Any CE specific string with additional parameters
        "XRSLMPExtraString" - Default = ""
               - Any CE specific string with additional parameters for MP jobs
        "ARCRESTTimeout"    - DEfault = 1.0 (seconds)
               - Timeout for the rest query
        "proxyTimeLeftBeforeRenewal" - Default = 10000 (seconds)
               - As the name says

        Note : This is not run from __init__ as the design of DIRAC means that ceParameters is
        as yet only filled with CEDefaults at the time this class is initialised for the given CE
        """
        if hasattr(self, "s"):
            # Initialisation has already been successfully ran
            return True
        self.log.debug("Testing if the REST interface is available", "for %s" % self.ceHost)

        print("-------------------------------->>>>>>>>>>>>>>>>>>>>>>>>>")
        print(self.ceHost)
        print(self.ceParameters)
        print(self.mandatoryParameters)
        print("XRSLExtraString : ", self.ceParameters.get('XRSLExtraString', ""))
        print("-------------------------------->>>>>>>>>>>>>>>>>>>>>>>>>")

        # First get the proxy ready
        result = self._prepareProxy()
        if not result["OK"]:  # Probably everything is going to fail?
            self.log.info("No proxy found -  Probably just no jobs to run for this CE?")
            self.log.info("Setting REST interface false.")
            return False

        # Set useful variables from the ceParameters
        variable = "proxyTimeLeftBeforeRenewal"
        self.proxyTimeLeftBeforeRenewal = 10000  # 2 hours, 46 minutes and 40 seconds
        if variable in self.ceParameters.keys():
            self.proxyTimeLeftBeforeRenewal = self.ceParameters[variable]
        self.log.debug(f"Setting {variable} to {self.proxyTimeLeftBeforeRenewal} for CE", self.ceHost )

        variable = "ARCRESTTimeout"
        self.arcRESTTimeout = 1.0
        if variable in self.ceParameters.keys():
            self.arcRESTTimeout = self.ceParameters[variable]
        self.log.debug(f"Setting {variable} to {self.arcRESTTimeout} for CE", self.ceHost )

        variable = "XRSLExtraString"
        self.xrslExtraString = ""
        if variable in self.ceParameters.keys():
            self.xrslExtraString = self.ceParameters[variable]
        self.log.debug(f"Setting {variable} to {self.xrslExtraString} for CE", self.ceHost )

        variable = "XRSLMPExtraString"
        self.xrslMPExtraString = ""
        if variable in self.ceParameters.keys():
            self.xrslMPExtraString = self.ceParameters[variable]
        self.log.debug(f"Setting {variable} to {self.xrslMPExtraString} for CE", self.ceHost )

        # Get the REST endpoint (service_url in ARC language) from the CS if available (preferred).
        # Otherwise query the CE for this value.

        # Try getting service_url from the CS
        variable = "RESTEndpoint"
        service_url = ""
        if variable in self.ceParameters.keys():
            service_url = self.ceParameters[variable]
        if len(service_url) < 5:  # There is no endpoint in the CS. Discover it.
            # The following command should expand to for example
            # ldapsearch -x -LLL -h grendel.hec.lancs.ac.uk:2135 -b 'o=glue' GLUE2EndpointInterfaceName=org.nordugrid.arcrest GLUE2EndpointURL | grep GLUE2EndpointURL | awk -F ": " '{print $2}'
            server = ldap3.Server("ldap://" + self.ceHost + ":2135")
            try:
                connection = ldap3.Connection(server, client_strategy=ldap3.SAFE_SYNC, auto_bind=True)
            except ldap3.core.exceptions.LDAPSocketOpenError:
                self.log.error("Could not connect to server", "CE : %s:2135" % self.ceHost)
                return False
            status, result, response, _ = connection.search(
                "o=glue", "(GLUE2EndpointInterfaceName=org.nordugrid.arcrest)", attributes="GLUE2EndpointURL"
            )
            if not status or len(response) == 0:
                self.log.error("Bad status from LDAP search", result)
                return False
            if len(response) != 1:
                self.log.warn("Expected one endpoint, got %s. Using the first." % len(response))
            # For some reason the response is of class "bytes"
            service_url = response[0]["raw_attributes"]["GLUE2EndpointURL"][  # pylint: disable=unsubscriptable-object
                0
            ].decode()

        # We now have a pointer (service_url) to the REST interface for this CE
        restVersion = "1.0"  # Will be this value for the forseeable future.
        self.base_url = service_url + "/rest/" + restVersion + "/"

        # Set up the request framework
        self.s = requests.Session()
        self.s.verify = Locations.getCAsLocation()
        self.headers = {"accept": "application/json", "Content-Type": "application/json"}

        return True

    #############################################################################
    def __writeXRSL(self, executableFile):
        """Create the JDL for submission"""
        diracStamp = makeGuid()[:8]
        # Evaluate the number of processors to allocate
        nProcessors = self.ceParameters.get("NumberOfProcessors", 1)

        xrslMPAdditions = ""
        if nProcessors and nProcessors > 1:
            xrslMPAdditions = """
(count = %(processors)u)
(countpernode = %(processorsPerNode)u)
%(xrslMPExtraString)s
      """ % {
                "processors": nProcessors,
                "processorsPerNode": nProcessors,  # This basically says that we want all processors on the same node
                "xrslMPExtraString": self.xrslMPExtraString,
            }

        xrsl = """
&(executable="%(executable)s")
(inputFiles=(%(executable)s "%(executableFile)s"))
(stdout="%(diracStamp)s.out")
(stderr="%(diracStamp)s.err")
(outputFiles=("%(diracStamp)s.out" "") ("%(diracStamp)s.err" ""))
(queue=%(queue)s)
%(xrslMPAdditions)s
%(xrslExtraString)s
    """ % {
            "executableFile": executableFile,
            "executable": os.path.basename(executableFile),
            "diracStamp": diracStamp,
            "queue": self.arcQueue,
            "xrslMPAdditions": xrslMPAdditions,
            "xrslExtraString": self.xrslExtraString,
        }

        return xrsl, diracStamp

    #############################################################################

    def _pilot_toAPI(self, pilot):
        # Add CE and protocol information to pilot ID
        if "://" in pilot:
            self.log.warn("Pilot already in API format", "%s" % pilot)
            return pilot
        pilotAPI = "gsiftp://" + self.ceHost + "/" + pilot
        # Uncomment if Federico really really wants this and comment the above line
        # base_url = "gsiftp://" + self.ceHost
        # pilotAPI = urljoin(base_url, pilot)
        return pilotAPI

    def _pilot_toREST(self, pilot):
        # Remove CE and protocol information from pilot ID
        if "://" in pilot:
            pilotREST = pilot.split("jobs/")[-1]
            return pilotREST
        self.log.warn("Pilot already in REST format?", "%s" % pilot)
        return pilot

    def _delegation(self, jobID):
        """Here we handle the delegations (Nordugrid language) = Proxy (Dirac language)
        Input jobID : the job identifier string (expected to be 56(?) chars for a normal job)

        If the jobID is empty (size < 2 chars) :
            Create and upload a new delegation to the CE and return the delegation ID
            This happens when the call is from the job submission function (self.submitJob). We want
        to attach a delegation to the XRSL strings we submit for each job, so that we can update
        this later if needed.
            More info at
            https://www.nordugrid.org/arc/arc6/users/xrsl.html#delegationid
            https://www.nordugrid.org/arc/arc6/tech/rest/rest.html#delegation-functionality

        If the jobID is not empty:
            Query and return the delegation ID of the given job
            This happens when the call is from self.renewJobs. This function needs to know the
        delegation associated to the job
            More info at
            https://www.nordugrid.org/arc/arc6/tech/rest/rest.html#jobs-management
            https://www.nordugrid.org/arc/arc6/tech/rest/rest.html#delegations-management
        """
        if len(jobID) < 2:  # New job(s) - create a delegation
            command = "delegations"
            params = {"action": "new"}
            query = self.base_url + command
            proxy = X509Chain()
            res = proxy.loadProxyFromFile(self.s.cert)
            r = self.s.post(
                query, data=proxy.dumpAllToString(), headers=self.headers, params=params, timeout=self.arcRESTTimeout
            )
            dID = ""
            if r.ok:  # Get the delegation and "PUT" it in the CE ...
                dID = r.headers.get("location", "")
                if len(dID) > 2:
                    dID = dID.split("new/")[-1]
                    command = "delegations/" + dID
                    query = self.base_url + command
                    r1 = self.s.put(query, data=r.text, headers=self.headers, timeout=self.arcRESTTimeout)
                    if not r1.ok:
                        dID = ""
                else:
                    dID = ""
            return dID
        else:  # Retrieve delegation for existing job
            jj = {"job": [{"id": jobID}]}  # job in ARC REST json format
            command = "jobs"
            params = {"action": "delegations"}
            query = self.base_url + command
            r = self.s.post(query, data=json.dumps(jj), headers=self.headers, timeout=self.arcRESTTimeout)
            dID = ""
            if r.ok:  # Check if the job has a delegation
                p = json.loads(r.text.replace("\n", ""))
                if "delegation_id" in p["job"]:
                    dID = p["job"]["delegation_id"][0]
            return dID

    #############################################################################
    def submitJob(self, executableFile, proxy, numberOfJobs=1):
        """Method to submit job
        Assume that the ARC queues are always of the format nordugrid-<batchSystem>-<queue>
        And none of our supported batch systems have a "-" in their name
        """
        if not self.initialised:  # Something went wrong in the initialisation. Redo it.
            return S_ERROR("REST interface not initialised. Cannot submit jobs.")

        self.arcQueue = self.queue.split("-", 2)[2]

        result = self._prepareProxy()
        if not result["OK"]:
            self.log.error("AREXComputingElement: failed to set up proxy", result["Message"])
            return result
        self.s.cert = Locations.getProxyLocation()

        self.log.verbose("Executable file path: %s" % executableFile)
        if not os.access(executableFile, 5):
            os.chmod(executableFile, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH + stat.S_IXOTH)

        batchIDList = []
        stampDict = {}

        command = "jobs"
        params = {"action": "new"}  # Is this the recommended way?
        query = self.base_url + command
        # First get a "delegation" and use the same delegation for all the jobs
        deleg = self._delegation("")
        deleText = ""
        if len(deleg) < 2:
            self.log.warn("Could not get a delegation for CE %s", self.ceHost)
            self.log.warn("Continue without a delegation")
        else:
            deleText = "(delegationid=%s)" % deleg
        # It is fairly simple to change to bulk submission. Should I do so?
        # https://www.nordugrid.org/arc/arc6/tech/rest/rest.html#job-submission-create-a-new-job
        for _ in range(numberOfJobs):
            # Get the job into the ARC way
            xrslString, diracStamp = self.__writeXRSL(executableFile)
            xrslString = xrslString + deleText  ### Needs to be tested.
            self.log.debug("XRSL string submitted is %s" % xrslString)
            self.log.debug("DIRAC stamp for job is %s" % diracStamp)
            r = self.s.post(query, data=xrslString, headers=self.headers, params=params, timeout=self.arcRESTTimeout)
            print("Job submission status : ", r.json()['job']['status-code'], type(r.json()['job']['status-code']))
            jobInfo = json.loads(r.text)['job']
            if r.ok and jobInfo['status-code'] != '500':
                # Job successfully submitted. Should I just test for == 201?
                pilotJobReference = self._pilot_toAPI(jobInfo["id"])
                batchIDList.append(pilotJobReference)
                stampDict[pilotJobReference] = diracStamp
                self.log.debug("Successfully submitted job", "%s to CE %s" % (pilotJobReference, self.ceHost))
            else:
                self.log.warn(
                    "Failed to submit job",
                    "to CE %s with error - %s - and message : %s"
                    % (self.ceHost, jobInfo['status-code'], jobInfo['reason']),
                )
                self.log.debug("DIRAC stamp and ARC job", "%s : %s" % (diracStamp, xrslString))
                break  # Boo hoo *sniff*

        if batchIDList:
            result = S_OK(batchIDList)
            result["PilotStampDict"] = stampDict
        else:
            result = S_ERROR("No pilot references obtained from the ARC job submission")
        return result

    #############################################################################
    def killJob(self, jobIDList):
        """Kill the specified jobs"""

        if not self.initialised:  # Something went wrong in the initialisation. Redo it.
            return S_ERROR("REST interface not initialised. Cannot kill jobs.")

        result = self._prepareProxy()
        if not result["OK"]:
            self.log.error("AREXComputingElement: failed to set up proxy", result["Message"])
            return result
        self.s.cert = Locations.getProxyLocation()

        self.log.debug("Killing jobs", ",".join(jobIDList))
        jList = [self._pilot_toREST(job) for job in jobIDList]

        # List of jobs in json format for the REST query
        jj = {"job": [{"id": job} for job in jList]}

        command = "jobs"
        params = {"action": "kill"}
        query = self.base_url + command
        # Killing jobs should be fast - bulk timeout of 10 seconds * basicTimeoutValue should be okay(?)
        r = self.s.post(query, data=jj, headers=self.headers, params=params, timeout=10.0 * self.arcRESTTimeout)
        if r.ok:
            # Job successfully submitted
            self.log.debug("Successfully deleted jobs %s " % (json.loads(r.text)))
        else:
            return S_ERROR("Failed to kill all these jobs: %s" % json.loads(r.text))

        return S_OK()

    #############################################################################
    def getCEStatus(self):
        """Method to return information on running and pending jobs.
        Query the CE directly to get the number of waiting and running jobs for the given
        VO and queue.
        The specification is apparently in glue2 and if you do a raw print out of the information
        it goes on and on as it dumps the full configuration of the CE for all VOs, queues,
        states and parameters. Hopefully this function weeds out everything except the relevant
        queue.
        """

        if not self.initialised:  # Something went wrong in the initialisation. Redo it.
            return S_ERROR("REST interface not initialised. Cannot get CE status.")

        result = self._prepareProxy()
        if not result["OK"]:
            self.log.error("AREXComputingElement: failed to set up proxy", result["Message"])
            return result
        self.s.cert = Locations.getProxyLocation()

        # Try to find out which VO we are running for. Essential now for REST interface.
        res = getVOfromProxyGroup()
        vo = res["Value"] if res["OK"] else ""

        result = S_OK()
        result["SubmittedJobs"] = 0
        command = "info"
        params = {"schema": "glue2"}
        query = self.base_url + command
        r = self.s.get(query, headers=self.headers, params=params, timeout=5.0 * self.arcRESTTimeout)

        if not r.ok:
            res = S_ERROR("Unknown failure for CE %s. Is the CE down?" % self.ceHost)
            return res

        p = json.loads(r.text)

        # Look only in the relevant section out of the headache
        info = p["Domains"]["AdminDomain"]["Services"]["ComputingService"]["ComputingShare"]

        # I have only seen the VO published in lower case ...
        magic = self.queue + "_" + vo.lower()
        for i in range(len(info)):
            if info[i]["ID"].endswith(magic):
                result["RunningJobs"] = info[i]["RunningJobs"]
                result["WaitingJobs"] = info[i]["WaitingJobs"]
                break  # Pick the first (should be only ...) matching queue + VO

        return result

    #############################################################################
    def _renewJobs(self, jobList):
        """Written for the REST interface - jobList is already in the REST format
        This function is called only by this class, NOT by the SiteDirector"""
        for job in jobList:
            # First get the delegation (proxy)
            dID = self._delegation(job)
            if len(dID) < 2:  # No delegation.
                continue

            # Get the proxy
            command = "delegations/" + dID
            params = {"action": "get"}
            query = self.base_url + command
            r = self.s.post(query, headers=self.headers, params=params, timeout=self.arcRESTTimeout)
            proxy = X509Chain.loadChainFromString(r.text)
            # Keep the following lines of code while waiting to test out the above line

            # # We need to write the proxy out to get its information
            # tmpProxyFile = "/tmp/arcRestRenew-" + makeGuid()[:8]
            # with open(tmpProxyFile, 'w') as outFile: outFile.write(r.text)
            # proxy = getProxyInfo(tmpProxyFile)
            # os.unlink(tmpProxyFile) # Cleanup

            # Now test and renew the proxy
            if not proxy["OK"] or "secondsLeft" not in proxy["Value"]:
                continue  # Proxy not okay or does not have "secondsLeft"
            timeLeft = int(proxy["Value"]["secondsLeft"])
            if timeLeft < self.proxyTimeLeftBeforeRenewal:
                self.log.debug("Renewing proxy for job", "%s whose proxy expires at %s" % (job, timeLeft))
                # Proxy needs to be renewd - try to renew it
                command = "delegations/" + dID
                params = {"action": "renew"}
                query = self.base_url + command
                r = self.s.post(query, headers=self.headers, params=params, timeout=self.arcRESTTimeout)
                if r.ok:
                    self.log.debug("Proxy successfully renewed", "for job %s" % job)
                else:
                    self.log.debug("Proxy not renewed", "for job %s with delegation %s" % (job, dID))
            else:  # No need to renew. Proxy is long enough
                continue

    #############################################################################
    def getJobStatus(self, jobIDList):
        """Get the status information for the given list of jobs"""

        if not self.initialised:  # Something went wrong in the initialisation. Redo it.
            return S_ERROR("REST interface not initialised. Cannot get job status.")

        result = self._prepareProxy()
        if not result["OK"]:
            self.log.error("AREXComputingElement: failed to set up proxy", result["Message"])
            return result
        self.s.cert = Locations.getProxyLocation()

        jobTmpList = list(jobIDList)
        if isinstance(jobIDList, six.string_types):
            jobTmpList = [jobIDList]

        # Pilots are stored with a DIRAC stamp (":::XXXXX") appended
        jobList = []
        for j in jobTmpList:
            job = j.split(":::")[0]
            jobList.append(job)

        self.log.debug("Getting status of jobs : %s" % jobList)

        # List of jobs in json format for the REST query
        jj = {"job": [{"id": self._pilot_toREST(job)} for job in jobList]}

        command = "jobs"
        params = {"action": "status"}
        query = self.base_url + command
        # Assume it takes 1 second per pilot and timeout accordingly?
        r = self.s.post(
            query, data=jj, headers=self.headers, params=params, timeout=float(len(jobList) * self.arcRESTTimeout)
        )
        if not r.ok:
            self.log.info("Failed getting the status of the jobs")
            return S_ERROR("Failed getting the status of the jobs")

        p = json.loads(r.text)
        resultDict = {}
        jobsToRenew = []
        jobsToCancel = []
        for job in p["job"]:
            jobID = self._pilot_toAPI(job["id"])
            # ARC REST interface returns hyperbole
            arcState = job["state"].capitalize()
            self.log.debug("REST ARC status", "for job %s is %s" % (jobID, arcState))
            resultDict[jobID] = self.mapStates[arcState]
            # Renew proxy only of jobs which are running or queuing
            if arcState in ("Running", "Queuing"):
                jobsToRenew.append(job["id"])
            if arcState == "Hold":
                # Cancel held jobs so they don't sit in the queue forever
                jobsToCancel.append(job["id"])
                self.log.debug("Killing held job %s" % jobID)

        # Renew jobs to be renewed
        # Does not work at present - wait for a new release of ARC CEs for this.
        self._renewJobs(jobsToRenew)

        # Kill jobs to be killed
        self.killJob(jobsToCancel)

        return S_OK(resultDict)

    #############################################################################
    def getJobOutput(self, jobID, localDir=None):
        """Get the specified job standard output and error files. If the localDir is provided,
        the output is returned as file in this directory. Otherwise, the output is returned
        as strings.
        """
        if not self.initialised:  # Something went wrong in the initialisation. Redo it.
            return S_ERROR("REST interface not initialised. Cannot get job output.")

        result = self._prepareProxy()
        if not result["OK"]:
            self.log.error("AREXComputingElement: failed to set up proxy", result["Message"])
            return result
        self.s.cert = Locations.getProxyLocation()

        if ":::" in jobID:
            pilotRef, stamp = jobID.split(":::")
        else:
            pilotRef = jobID
            stamp = ""
        if not stamp:
            return S_ERROR("Pilot stamp not defined for %s" % pilotRef)

        arcID = os.path.basename(pilotRef)
        self.log.debug("Retrieving pilot logs", "for %s" % pilotRef)
        if "WorkingDirectory" in self.ceParameters:
            workingDirectory = os.path.join(self.ceParameters["WorkingDirectory"], arcID)
        else:
            workingDirectory = arcID
        outFileName = os.path.join(workingDirectory, "%s.out" % stamp)
        errFileName = os.path.join(workingDirectory, "%s.err" % stamp)
        self.log.debug("Working directory for pilot output %s" % workingDirectory)

        ##### I am not sure I have understood how DIRAC works here
        ##### But I hope that the previous looks have confirmed that this is how
        ##### the WMSAdministrator expects the results.
        mycwd = os.getcwd()
        os.makedirs(workingDirectory)
        os.chdir(workingDirectory)  # Retrieve the outputs here
        command = "jobs/"
        job = self._pilot_toREST(pilotRef)
        query = self.base_url + command + job + "/session/ " + stamp + ".out"
        # Give the CE 10 seconds to return the log. Is this enough?
        r = self.s.get(query, headers=self.headers, timeout=10.0 * self.arcRESTTimeout)
        if not r.ok:
            self.log.error("Error downloading stdout", "for %s: %s" % (job, r.text))
            return S_ERROR("Failed to retrieve at least some output for %s" % jobID)
        output = r.text
        query = self.base_url + command + job + "/session/ " + stamp + ".err"
        r = self.s.get(query, headers=self.headers, timeout=10.0 * self.arcRESTTimeout)
        if not r.ok:
            self.log.error("Error downloading stderr", "for %s: %s" % (job, r.text))
            return S_ERROR("Failed to retrieve at least some output for %s" % jobID)
        error = r.text

        os.chdir(mycwd)  # Reset the working directory just in case
        return S_OK((output, error))
