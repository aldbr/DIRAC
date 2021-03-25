"""
  The Job Agent class instantiates a CE that acts as a client to a
  compute resource and also to the WMS.
  The Job Agent constructs a classAd based on the local resource description in the CS
  and the current resource status that is used for matching.
"""

from __future__ import absolute_import
from __future__ import print_function

__RCSID__ = "$Id$"

import os
import sys
import re
import time

from DIRAC import S_OK, S_ERROR, gConfig
from DIRAC.Resources.Computing.BatchSystems.TimeLeft.TimeLeft import TimeLeft
from DIRAC.WorkloadManagementSystem.Client.PilotManagerClient import PilotManagerClient
from DIRAC.WorkloadManagementSystem.Client.JobReport import JobReport
from DIRAC.WorkloadManagementSystem.Utilities.AbstractJobAgent import AbstractJobAgent


class JobAgent(AbstractJobAgent):
  """ This agent is what runs in a worker node. The pilot runs it, after having prepared its configuration.
  """

  def __init__(self, agentName, loadName, baseAgentName=False, properties=None):
    """ Just defines some default parameters
    """
    super(JobAgent, self).__init__(agentName, loadName, baseAgentName, properties)

    self.pilotReference = 'Unknown'

    # Agent options
    # This is the factor to convert raw CPU to Normalized units (based on the CPU Model)
    self.minimumTimeLeft = 5000
    self.stopAfterFailedMatches = 10
    self.jobCount = 0
    self.matchFailedCount = 0
    self.fillingMode = True
    self.stopOnApplicationFailure = True

    # Timeleft
    self.initTimes = os.times()
    self.initTimeLeft = 0.0
    self.timeLeft = self.initTimeLeft
    self.timeLeftUtil = None
    self.pilotInfoReportedFlag = False

  def initialize(self):
    """Sets default parameters and creates CE instance
    """
    super(JobAgent, self).initialize()

    # Disable monitoring
    self.am_setOption('MonitoringEnabled', False)

    localCE = gConfig.getValue('/LocalSite/LocalCE', self.ceName)
    if localCE != self.ceName:
      self.log.info('Defining Inner CE from local configuration', '= %s' % localCE)

    result = self._initializeComputingElement(localCE)
    if not result['OK']:
      return result
    result = self._getCEDict(self.computingElement)
    if not result['OK']:
      return result
    ceDict = result['Value'][0]

    self.initTimeLeft = ceDict.get('CPUTime', self.initTimeLeft)
    self.initTimeLeft = gConfig.getValue('/Resources/Computing/CEDefaults/MaxCPUTime', self.initTimeLeft)
    self.timeLeft = self.initTimeLeft
    self.initTimes = os.times()

    # Localsite options
    self.siteName = gConfig.getValue('/LocalSite/Site', self.siteName)
    self.pilotReference = gConfig.getValue('/LocalSite/PilotReference', self.pilotReference)

    # Agent options
    # This is the factor to convert raw CPU to Normalized units (based on the CPU Model)
    self.cpuFactor = gConfig.getValue('/LocalSite/CPUNormalizationFactor', self.cpuFactor)
    self.fillingMode = self.am_getOption('FillingModeFlag', self.fillingMode)
    self.minimumTimeLeft = self.am_getOption('MinimumTimeLeft', self.minimumTimeLeft)
    self.stopOnApplicationFailure = self.am_getOption('StopOnApplicationFailure', self.stopOnApplicationFailure)
    self.stopAfterFailedMatches = self.am_getOption('StopAfterFailedMatches', self.stopAfterFailedMatches)

    # Timeleft
    self.timeLeftUtil = TimeLeft()
    return S_OK()

  def execute(self):
    """The JobAgent execution method.
    """
    # Temporary mechanism to pass a shutdown message to the agent
    if os.path.exists('/var/lib/dirac_drain'):
      return self._finish('Node is being drained by an operator')

    self.log.verbose('Job Agent execution loop')

    # Check that there is enough slots to match a job
    result = self._checkCEAvailability(self.computingElement)
    if not result['OK'] or (result['OK'] and result['Value'] not None):
      return result

    # Check that we are allowed to continue and that time left is sufficient
    if self.jobCount:
      cpuWorkLeft = self._computeCPUWorkLeft()
      result = self._checkCPUWorkLeft(cpuWorkleft)
      if not result['OK']:
        return result
      result = self._setCPUWorkLeft(cpuWorkLeft)
      if not result['OK']:
        return result

    # Get environment details and enhance them
    result = self._getCEDict(self.computingElement)
    if not result['OK']:
      return result
    ceDictList = result['Value']
    for ceDict in ceDictList:
      self._setCEDict(ceDict)

    # Try to match a job
    jobRequest = self._matchAJob(ceDictList)
    if not jobRequest['OK']:
      # if we don't match a job, independently from the reason,
      # we wait a bit longer before trying again
      self.am_setOption("PollingTime", int(self.am_getOption("PollingTime") * 1.5))
      return self._checkMatchingIssues(jobRequest['Message'])

    # Reset the Counter
    self.matchFailedCount = 0
    matcherInfo = jobRequest['Value']

    # Check matcher information returned
    matcherParams = ['JDL', 'DN', 'Group']
    result = self._checkMatcherInfo(matcherInfo, matcherParams)
    if not result['OK']:
      return result

    # Get matcher information
    if not self.pilotInfoReportedFlag:
      # Check the flag after the first access to the Matcher
      self.pilotInfoReportedFlag = matcherInfo.get('PilotInfoReportedFlag', False)

    jobJDL = matcherInfo['JDL']
    jobGroup = matcherInfo['Group']
    ownerDN = matcherInfo['DN']

    optimizerParams = {}
    for key in matcherInfo:
      if key not in matcherParams:
        optimizerParams[key] = matcherInfo[key]

    # Get JDL paramters
    result = self._getJDLParameters(jobJDL)
    if not result['OK']:
      self._report(jobID, 'Failed', 'Could Not Extract JDL Parameters')
      self.log.warn('Could Not Extract JDL Parameters', result['Message'])
      return self._finish('JDL Problem')

    params = result['Value']
    result = self._extractValuesFromJobParams(params)
    if not result['OK']:
      return result
    submissionParams = result['Value']
    jobID = submissionParams['jobID']
    jobType = submissionParams['jobType']

    self.log.verbose('Job request successful: \n', jobRequest['Value'])
    self.log.info('Received', 'JobID=%s, JobType=%s, OwnerDN=%s, JobGroup=%s' % (jobID, jobType, ownerDN, jobGroup))
    self.jobCount += 1
    try:
      jobReport = JobReport(jobID, 'JobAgent@%s' % self.siteName)
      jobReport.setJobParameter('MatcherServiceTime', str(matcherInfo['matchTime']), sendFlag=False)

      if 'BOINC_JOB_ID' in os.environ:
        # Report BOINC environment
        for thisp in ('BoincUserID', 'BoincHostID', 'BoincHostPlatform', 'BoincHostName'):
          jobReport.setJobParameter(thisp, gConfig.getValue('/LocalSite/%s' % thisp, 'Unknown'), sendFlag=False)

      jobReport.setJobStatus('Matched', 'Job Received by Agent')

      # Setup proxy
      result = self._setupProxy(ownerDN, jobGroup)
      if not result['OK']:
        return self._rescheduleFailedJob(jobID, result['Message'], self.stopOnApplicationFailure)
      proxyChain = result.get('Value')

      # Save the job jdl for external monitoring
      self._saveJobJDLRequest(jobID, jobJDL)

      # Check software and install them if required
      software = self._checkInstallSoftware(jobID, params, ceDict)
      if not software['OK']:
        self.log.error('Failed to install software for job', '%s' % (jobID))
        errorMsg = software['Message']
        if not errorMsg:
          errorMsg = 'Failed software installation'
        return self._rescheduleFailedJob(jobID, errorMsg, self.stopOnApplicationFailure)

      # Submit the job to the CE
      self.log.debug('Before self._submitJob() (%sCE)' % (self.ceName))
      result = self._submitJob(jobID, params, ceDict, optimizerParams, proxyChain,
                               submissionParams['processors'],
                               submissionParams['wholeNode'],
                               submissionParams['maxNumberOfProcessors'],
                               submissionParams['mpTag'],
                               stop=self.stopOnApplicationFailure)
      if not result['OK']:
        return self._finish(result['Message'])
      elif 'PayloadFailed' in result:
        # Do not keep running and do not overwrite the Payload error
        message = 'Payload execution failed with error code %s' % result['PayloadFailed']
        if self.stopOnApplicationFailure:
          return self._finish(message, self.stopOnApplicationFailure)
        else:
          self.log.info(message)
      self.log.debug('After %sCE submitJob()' % (self.ceName))

    except Exception as subExcept:  # pylint: disable=broad-except
      self.log.exception("Exception in submission", "", lException=subExcept, lExcInfo=True)
      return self._rescheduleFailedJob(jobID, 'Job processing failed with exception', self.stopOnApplicationFailure)

    return S_OK('Job Agent cycle complete')

  def finalize(self):
    """ Job Agent finalization method
    """
    gridCE = gConfig.getValue('/LocalSite/GridCE', '')
    queue = gConfig.getValue('/LocalSite/CEQueue', '')
    result = PilotManagerClient().setPilotStatus(str(self.pilotReference), 'Done', gridCE,
                                                 'Report from JobAgent', self.siteName, queue)
    if not result['OK']:
      self.log.warn('Issue setting the pilot status', result['Message'])

    return S_OK()

  # --------------------------------------------------------------------------------------------------------------

  def _computeCPUWorkLeft(self, processors=1):
    """
    Compute CPU Work Left in hepspec06 seconds

    :param int processors: number of processors available
    :return: cpu work left (cpu time left * cpu power of the cpus)
    """
    # Sum all times but the last one (elapsed_time) and remove times at init (is this correct?)
    cpuTime = sum(os.times()[:-1]) - sum(self.initTimes[:-1])
    result = self.timeLeftUtil.getTimeLeft(cpuTime, processors)
    if not result['OK']:
      self.log.warn("There were errors calculating time left using the Timeleft utility", result['Message'])
      self.log.warn("The time left will be calculated using os.times() and the info in our possession")
      self.log.info('Current raw CPU time consumed is %s' % cpuConsumed)
      if self.cpuFactor:
        return self.initTimeLeft - cpuConsumed * self.cpuFactor
      return self.timeLeft

    return result['Value']

  def _checkCPUWorkLeft(self, cpuWorkLeft):
    """ Check that fillingMode is enabled and time left is sufficient to continue the execution
    """
    # Only call timeLeft utility after a job has been picked up
    self.log.info('Attempting to check CPU time left for filling mode')
    if not self.fillingMode:
      return self._finish('Filling Mode is Disabled')

    self.log.info('normalized CPU units remaining in slot', cpuWorkLeft)
    if cpuWorkLeft <= self.minimumTimeLeft:
      return self._finish('No more time left')

    return S_OK()

  def _setCPUWorkLeft(self, cpuWorkLeft):
    """ Update the TimeLeft within the CE and the configuration for next matching request
    """
    self.timeLeft = cpuWorkLeft

    result = self.computingElement.setCPUTimeLeft(cpuTimeLeft=self.timeLeft)
    if not result['OK']:
      return self._finish(result['Message'])

    self._updateLocalConfiguration('CPUTimeLeft', self.timeleft)
    return S_OK()

  # --------------------------------------------------------------------------------------------------------------


  def _setCEDict(self, ceDict):
    """ Set CEDict
    """
    # Add pilot information
    gridCE = gConfig.getValue('LocalSite/GridCE', 'Unknown')
    if gridCE != 'Unknown':
      ceDict['GridCE'] = gridCE
    if 'PilotReference' not in ceDict:
      ceDict['PilotReference'] = str(self.pilotReference)
    ceDict['PilotBenchmark'] = self.cpuFactor
    ceDict['PilotInfoReportedFlag'] = self.pilotInfoReportedFlag

    # Add possible job requirements
    result = gConfig.getOptionsDict('/AgentJobRequirements')
    if result['OK']:
      requirementsDict = result['Value']
      ceDict.update(requirementsDict)
      self.log.info('Requirements:', requirementsDict)

  def _checkMatchingIssues(self, issueMessage):
    """
    """
    if issueMessage.find("Pilot version does not match") != -1:
      errorMsg = 'Pilot version does not match the production version'
      self.log.error(errorMsg, issueMessage.replace(errorMsg, ''))
      return S_ERROR(issueMessage)

    matchingFailed = False
    if re.search('No match found', issueMessage):
      self.log.notice('Job request OK, but no match found', ': %s' % issueMessage)
    elif issueMessage.find("seconds timeout") != -1:
      self.log.error('Timeout while requesting job', issueMessage)
    else:
      self.log.notice('Failed to get jobs', ': %s' % issueMessage)

    self.matchFailedCount += 1
    if self.matchFailedCount > self.stopAfterFailedMatches:
      return self._finish('Nothing to do for more than %d cycles' % self.stopAfterFailedMatches)
    return S_OK(issueMessage)
