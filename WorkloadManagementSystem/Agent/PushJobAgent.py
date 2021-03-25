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
import six
import random

from DIRAC import S_OK, S_ERROR, gConfig
from DIRAC.Core.Utilities.ObjectLoader import ObjectLoader
from DIRAC.ConfigurationSystem.Client.Helpers.Operations import Operations
from DIRAC.WorkloadManagementSystem.Client.JobReport import JobReport
from DIRAC.WorkloadManagementSystem.Utilities.QueueUtilities import getQueuesResolvedEnhanced
from DIRAC.WorkloadManagementSystem.Service.WMSUtilities import getGridEnv
from DIRAC.WorkloadManagementSystem.Utilities.AbstractJobAgent import AbstractJobAgent


class PushJobAgent(AbstractJobAgent):
  """ This agent is what runs in a worker node. The pilot runs it, after having prepared its configuration.
  """

  def __init__(self, agentName, loadName, baseAgentName=False, properties=None):
    """ Just defines some default parameters
    """
    super(PushJobAgent, self).__init__(agentName, loadName, baseAgentName, properties)
    self.firstPass = True

  def initialize(self):
    """Sets default parameters and creates CE instance
    """
    super(PushJobAgent, self).initialize()

    # Disable monitoring
    self.am_setOption('MonitoringEnabled', False)

    result = self._initializeComputingElement('Pool')
    if not result['OK']:
      return result
    self.computingElement.setParameters({'NumberOfProcessors': 100})

    # on-the fly imports
    ol = ObjectLoader()
    res = ol.loadModule("ConfigurationSystem.Client.Helpers.Resources")
    if not res['OK']:
      sys.exit(res['Message'])
    self.resourcesModule = res['Value']
    self.queueCECache = {}

    self.opsHelper = Operations()

    return S_OK()

  def beginExecution(self):
    """ This is run at every cycles, as first thing.
    It gets site, CE and queue descriptions.
    """
    siteNames = None
    siteNamesOption = self.am_getOption('Site', ['any'])
    if siteNamesOption and 'any' not in [sn.lower() for sn in siteNamesOption]:
      siteNames = siteNamesOption

    ceTypes = None
    ceTypesOption = self.am_getOption('CETypes', ['any'])
    if ceTypesOption and 'any' not in [ct.lower() for ct in ceTypesOption]:
      ceTypes = ceTypesOption

    ces = None
    cesOption = self.am_getOption('CEs', ['any'])
    if cesOption and 'any' not in [ce.lower() for ce in cesOption]:
      ces = cesOption

    self.log.info('Sites:', siteNames)
    self.log.info('CETypes:', ceTypes)
    self.log.info('CEs:', ces)

    result = self.buildQueueDict(siteNames, ces, ceTypes)
    if not result['OK']:
      return result

    self.queueDict = result['Value']

    if self.firstPass:
      if self.queueDict:
        self.log.always("Agent will serve queues:")
        for queue in self.queueDict:
          self.log.always("Site: %s, CE: %s, Queue: %s" % (self.queueDict[queue]['Site'],
                                                           self.queueDict[queue]['CEName'],
                                                           queue))
    self.firstPass = False
    return S_OK()

  def execute(self):
    """The JobAgent execution method.
    """
    self.log.verbose('Job Agent execution loop')

    queueDictItems = list(self.queueDict.items())
    random.shuffle(queueDictItems)

    for queueName, queueDictionary in queueDictItems:
      ce = queueDictionary['CE']

      workloadExecLocation = "%s:%s:%s" % (queueDictionary['Site'],
                                           queueDictionary['CEName'],
                                           queueDictionary['QueueName'])
      self._updateLocalConfiguration('WorkloadExecLocation', workloadExecLocation)

      # Check that there is enough slots to match a job
      result = self._checkCEAvailability(ce)
      if not result['OK']:
        return result

      # Get environment details and enhance them
      result = self._getCEDict(ce)
      if not result['OK']:
        return result
      ceDictList = result['Value']
      for ceDict in ceDictList:
        self._setCEDict(ceDict)

      # Try to match a job
      jobRequest = self._matchAJob(ceDictList)
      if not jobRequest['OK']:
        return self._checkMatchingIssues(jobRequest['Message'])

      matcherInfo = jobRequest['Value']

      # Check matcher information returned
      matcherParams = ['JDL', 'DN', 'Group']
      result = self._checkMatcherInfo(matcherInfo, matcherParams)
      if not result['OK']:
        return result

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
      try:
        jobReport = JobReport(jobID, 'JobAgent@%s' % self.siteName)
        jobReport.setJobParameter('MatcherServiceTime', str(matcherInfo['matchTime']), sendFlag=False)

        jobReport.setJobStatus('Matched', 'Job Received by Agent')

        # Setup proxy
        result = self._setupProxy(ownerDN, jobGroup)
        if not result['OK']:
          return self._rescheduleFailedJob(jobID, result['Message'], False)
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
          return self._rescheduleFailedJob(jobID, errorMsg, False)

        # Submit the job to the CE
        self.log.debug('Before self._submitJob() (%sCE)' % (self.ceName))
        result = self._submitJob(jobID, params, ceDict, optimizerParams, proxyChain,
                                 submissionParams['processors'],
                                 submissionParams['wholeNode'],
                                 submissionParams['maxNumberOfProcessors'],
                                 submissionParams['mpTag'])
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
        return self._rescheduleFailedJob(jobID, 'Job processing failed with exception', False)

    return S_OK('Job Agent cycle complete')

  # --------------------------------------------------------------------------------------------------------------

  def buildQueueDict(self, siteNames, ces, ceTypes):
    """
    """
    result = self.resourcesModule.getQueues(community='',
                                            siteList=siteNames,
                                            ceList=ces,
                                            ceTypeList=ceTypes,
                                            mode='Direct')
    if not result['OK']:
      return result

    result = getQueuesResolvedEnhanced(siteDict=result['Value'],
                                       queueCECache=self.queueCECache,
                                       gridEnv=getGridEnv(),
                                       setup=gConfig.getValue('/DIRAC/Setup', 'unknown'))
    if not result['OK']:
      return result

    return S_OK(result['Value'])

  def _setCEDict(self, ceDict):
    """ Set CEDict
    """
    # Matcher will check that ReleaseVersion match the pilot version
    # It is not needed in this configuration so we set ReleaseVersion as the pilot version
    versions = self.opsHelper.getValue("Pilot/Version", [])
    if versions:
      ceDict['ReleaseVersion'] = versions[0]
    project = self.opsHelper.getValue("Pilot/Project", "")
    if project:
      ceDict['ReleaseProject'] = project

  def _checkMatchingIssues(self, issueMessage):
    """
    """
    matchingFailed = False
    if re.search('No match found', issueMessage):
      self.log.notice('Job request OK, but no match found', ': %s' % issueMessage)
    elif issueMessage.find("seconds timeout") != -1:
      self.log.error('Timeout while requesting job', issueMessage)
    else:
      self.log.notice('Failed to get jobs', ': %s' % issueMessage)

    return S_OK(issueMessage)