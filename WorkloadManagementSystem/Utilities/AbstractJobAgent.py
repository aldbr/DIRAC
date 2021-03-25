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

from DIRAC import S_OK, S_ERROR, gConfig, rootPath
from DIRAC.Core.Utilities.ModuleFactory import ModuleFactory
from DIRAC.Core.Utilities.ClassAd.ClassAdLight import ClassAd
from DIRAC.Resources.Computing.BatchSystems.TimeLeft.TimeLeft import TimeLeft
from DIRAC.Core.Utilities.CFG import CFG
from DIRAC.Core.Base.AgentModule import AgentModule
from DIRAC.Core.Security.ProxyInfo import getProxyInfo
from DIRAC.Core.Security import Properties
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
from DIRAC.WorkloadManagementSystem.Client.JobStateUpdateClient import JobStateUpdateClient
from DIRAC.WorkloadManagementSystem.Client.JobManagerClient import JobManagerClient
from DIRAC.WorkloadManagementSystem.Client.PilotManagerClient import PilotManagerClient
from DIRAC.Resources.Computing.ComputingElementFactory import ComputingElementFactory
from DIRAC.WorkloadManagementSystem.Client.JobReport import JobReport
from DIRAC.WorkloadManagementSystem.Client.MatcherClient import MatcherClient
from DIRAC.WorkloadManagementSystem.Utilities.Utils import createJobWrapper


class AbstractJobAgent(AgentModule):
  """ This agent is what runs in a worker node. The pilot runs it, after having prepared its configuration.
  """

  def __init__(self, agentName, loadName, baseAgentName=False, properties=None):
    """ Just defines some default parameters
    """
    if not properties:
      properties = {}
    super(AbstractJobAgent, self).__init__(agentName, loadName, baseAgentName, properties)

    # Inner CE
    # CE type the JobAgent submits to. It can be "InProcess" or "Pool" or "Singularity".
    self.ceName = 'InProcess'
    # "Inner" CE submission type (e.g. for Pool CE). It can be "InProcess" or "Singularity".
    self.innerCESubmissionType = 'InProcess'
    self.computingElement = None  # The ComputingElement object, e.g. SingularityComputingElement()

    # Localsite options
    self.siteName = 'Unknown'
    self.defaultProxyLength = 86400 * 5

    # Agent options
    # This is the factor to convert raw CPU to Normalized units (based on the CPU Model)
    self.cpuFactor = 0.0
    self.jobSubmissionDelay = 10
    self.extraOptions = ''

    # Timeleft
    self.timeLeft = 0.0

  def initialize(self):
    """Sets default parameters and creates CE instance
    """
    self.defaultProxyLength = gConfig.getValue('/Registry/DefaultProxyLifeTime', self.defaultProxyLength)
    self.jobSubmissionDelay = self.am_getOption('SubmissionDelay', self.jobSubmissionDelay)
    self.extraOptions = gConfig.getValue('/AgentJobRequirements/ExtraOptions', self.extraOptions)
    return S_OK()

  def _initializeComputingElement(self, localCE):
    """ Generate a ComputingElement and configure it
    """
    ceFactory = ComputingElementFactory()
    self.ceName = localCE.split('/')[0]  # It might be "Pool/Singularity", or simply "Pool"
    self.innerCESubmissionType = localCE.split('/')[1] if len(localCE.split('/')) == 2 else self.innerCESubmissionType
    ceInstance = ceFactory.getCE(self.ceName)
    if not ceInstance['OK']:
      self.log.warn("Can't instantiate a CE", ceInstance['Message'])
      return ceInstance
    self.computingElement = ceInstance['Value']
    self.computingElement.ceParameters['InnerCESubmissionType'] = self.innerCESubmissionType
    return S_OK()

  # --------------------------------------------------------------------------------------------------------------

  def execute(self):
    """The JobAgent execution method.
    """
    raise NotImplementedError("execute() to implemented")

  # --------------------------------------------------------------------------------------------------------------

  def _updateLocalConfiguration(self, key, value):
    """ Update local configuration to be used by submitted job wrappers
    """
    localCfg = CFG()
    if self.extraOptions:
      localConfigFile = os.path.join('.', self.extraOptions)
    else:
      localConfigFile = os.path.join(rootPath, "etc", "dirac.cfg")
    localCfg.loadFromFile(localConfigFile)
    if not localCfg.isSection('/LocalSite'):
      localCfg.createNewSection('/LocalSite')
    localCfg.setOption('/LocalSite/%s' % key, value)
    localCfg.writeToFile(localConfigFile)

  def _setupProxy(self, ownerDN, ownerGroup):
    """
    Retrieve a proxy for the execution of the job
    """
    if gConfig.getValue('/DIRAC/Security/UseServerCertificate', False):
      proxyResult = self._requestProxyFromProxyManager(ownerDN, ownerGroup)
      if not proxyResult['OK']:
        self.log.error('Failed to setup proxy', proxyResult['Message'])
        return S_ERROR('Failed to setup proxy: %s' % proxyResult['Message'])
      return S_OK(proxyResult['Value'])
    else:
      ret = getProxyInfo(disableVOMS=True)
      if not ret['OK']:
        self.log.error('Invalid Proxy', ret['Message'])
        return S_ERROR('Invalid Proxy')

      proxyChain = ret['Value']['chain']
      if 'groupProperties' not in ret['Value']:
        print(ret['Value'])
        print(proxyChain.dumpAllToString())
        self.log.error('Invalid Proxy', 'Group has no properties defined')
        return S_ERROR('Proxy has no group properties defined')

      groupProps = ret['Value']['groupProperties']
      if Properties.GENERIC_PILOT in groupProps or Properties.PILOT in groupProps:
        proxyResult = self._requestProxyFromProxyManager(ownerDN, ownerGroup)
        if not proxyResult['OK']:
          self.log.error('Invalid Proxy', proxyResult['Message'])
          return S_ERROR('Failed to setup proxy: %s' % proxyResult['Message'])
        proxyChain = proxyResult['Value']

    return S_OK(proxyChain)

  def _requestProxyFromProxyManager(self, ownerDN, ownerGroup):
    """Retrieves user proxy with correct role for job and sets up environment to
       run job locally.
    """

    self.log.info("Requesting proxy', 'for %s@%s" % (ownerDN, ownerGroup))
    token = gConfig.getValue("/Security/ProxyToken", "")
    if not token:
      self.log.verbose("No token defined. Trying to download proxy without token")
      token = False
    retVal = gProxyManager.getPayloadProxyFromDIRACGroup(ownerDN, ownerGroup,
                                                         self.defaultProxyLength, token)
    if not retVal['OK']:
      self.log.error('Could not retrieve payload proxy', retVal['Message'])
      os.system('dirac-proxy-info')
      sys.stdout.flush()
      return S_ERROR('Error retrieving proxy')

    chain = retVal['Value']
    return S_OK(chain)

  # --------------------------------------------------------------------------------------------------------------

  def _checkCEAvailability(self, computingElement):
    result = computingElement.available()
    if not result['OK']:
      self.log.info('Resource is not available', result['Message'])
      return self._finish('CE Not Available')

    ceInfoDict = result['CEInfoDict']
    runningJobs = ceInfoDict.get("RunningJobs")
    availableSlots = result['Value']

    if not availableSlots:
      if runningJobs:
        self.log.info('No available slots', ': %d running jobs' % runningJobs)
        return S_OK('Job Agent cycle complete with %d running jobs' % runningJobs)
      self.log.info('CE is not available (and there are no running jobs)')
      return self._finish('CE Not Available')
    return S_OK()

  def _checkInstallSoftware(self, jobID, jobParams, resourceParams):
    """Checks software requirement of job and whether this is already present
       before installing software locally.
    """
    if 'SoftwareDistModule' not in jobParams:
      msg = 'Job has no software installation requirement'
      self.log.verbose(msg)
      return S_OK(msg)

    self._report(jobID, 'Matched', 'Installing Software')
    softwareDist = jobParams['SoftwareDistModule']
    self.log.verbose('Found VO Software Distribution module', ': %s' % (softwareDist))
    argumentsDict = {'Job': jobParams, 'CE': resourceParams}
    moduleFactory = ModuleFactory()
    moduleInstance = moduleFactory.getModule(softwareDist, argumentsDict)
    if not moduleInstance['OK']:
      return moduleInstance

    module = moduleInstance['Value']
    return module.execute()

  def _getCEDict(self, computingElement):
    """ Get CE description
    """
    # if we are here we assume that a job can be matched
    result = computingElement.getDescription()
    if not result['OK']:
      self.log.warn("Can not get the CE description")
      return result

    # We can have several prioritized job retrieval strategies
    if isinstance(result['Value'], dict):
      ceDictList = [result['Value']]
    elif isinstance(result['Value'], list):
      # This is the case for Pool ComputingElement, and parameter 'MultiProcessorStrategy'
      ceDictList = result['Value']

    return S_OK(ceDictList)

  def _setCEDict(ceDict):
    """ Set CEDict: can be overriden
    """
    pass

  def _matchAJob(self, ceDictList):
    """ Call the Matcher with each ceDict until we get a job
    """
    for ceDict in ceDictList:
      self.log.verbose('CE dict', ceDict)

      start = time.time()
      jobRequest = MatcherClient().requestJob(ceDict)
      matchTime = time.time() - start

      self.log.info('MatcherTime', '= %.2f (s)' % (matchTime))
      if jobRequest['OK']:
        jobRequest['Value']['matchTime'] = matchTime
        break
    return jobRequest

  def _checkMatcherInfo(self, matcherInfo, matcherParams):
    """ Check that all relevant information about the job are available
    """
    jobID = matcherInfo['JobID']
    for param in matcherParams:
      if param not in matcherInfo:
        self._report(jobID, 'Failed', 'Matcher did not return %s' % (param))
        return self._finish('Matcher Failed')

      if not matcherInfo[param]:
        self._report(jobID, 'Failed', 'Matcher returned null %s' % (param))
        return self._finish('Matcher Failed')

      self.log.verbose('Matcher returned', '%s = %s ' % (param, matcherInfo[param]))
    return S_OK()

  # --------------------------------------------------------------------------------------------------------------

  def _submitJob(self, jobID, jobParams, resourceParams, optimizerParams,
                 proxyChain,
                 processors=1, wholeNode=False, maxNumberOfProcessors=0, mpTag=False, stop=False):
    """ Submit job to the Computing Element instance after creating a custom
        Job Wrapper with the available job parameters.
    """
    logLevel = self.am_getOption('DefaultLogLevel', 'INFO')
    defaultWrapperLocation = self.am_getOption('JobWrapperTemplate',
                                               'DIRAC/WorkloadManagementSystem/JobWrapper/JobWrapperTemplate.py')

    # Add the number of requested processors to the job environment
    if 'ExecutionEnvironment' in jobParams:
      if isinstance(jobParams['ExecutionEnvironment'], six.string_types):
        jobParams['ExecutionEnvironment'] = jobParams['ExecutionEnvironment'].split(';')
    jobParams.setdefault('ExecutionEnvironment', []).append('DIRAC_JOB_PROCESSORS=%d' % processors)

    jobDesc = {"jobID": jobID,
               "jobParams": jobParams,
               "resourceParams": resourceParams,
               "optimizerParams": optimizerParams,
               "extraOptions": self.extraOptions,
               "defaultWrapperLocation": defaultWrapperLocation}
    result = createJobWrapper(log=self.log, logLevel=logLevel, **jobDesc)
    if not result['OK']:
      return result

    wrapperFile = result['Value']
    self._report(jobID, 'Matched', 'Submitted To CE')

    self.log.info('Submitting JobWrapper',
                  '%s to %sCE' % (os.path.basename(wrapperFile), self.ceName))

    # Pass proxy to the CE
    proxy = proxyChain.dumpAllToString()
    if not proxy['OK']:
      self.log.error('Invalid proxy', proxy)
      return S_ERROR('Payload Proxy Not Found')

    payloadProxy = proxy['Value']
    submission = self.computingElement.submitJob(wrapperFile, payloadProxy,
                                                 numberOfProcessors=processors,
                                                 maxNumberOfProcessors=maxNumberOfProcessors,
                                                 wholeNode=wholeNode,
                                                 mpTag=mpTag,
                                                 jobDesc=jobDesc,
                                                 log=self.log,
                                                 logLevel=logLevel)
    ret = S_OK('Job submitted')

    if submission['OK']:
      batchID = submission['Value']
      self.log.info('Job submitted', '(DIRAC JobID: %s; Batch ID: %s' % (jobID, batchID))
      if 'PayloadFailed' in submission:
        ret['PayloadFailed'] = submission['PayloadFailed']
        return ret
      time.sleep(self.jobSubmissionDelay)
    else:
      self.log.error('Job submission failed', jobID)
      self.__setJobParam(jobID, 'ErrorMessage', '%s CE Submission Error' % (self.ceName))
      if 'ReschedulePayload' in submission:
        self._rescheduleFailedJob(jobID, submission['Message'], stop)
        return S_OK()  # Without this, the job is marked as failed
      else:
        if 'Value' in submission:
          self.log.error('Error in DIRAC JobWrapper or inner CE execution:',
                         'exit code = %s' % (str(submission['Value'])))
      self.log.error("CE Error", "%s : %s" % (self.ceName, submission['Message']))
      return submission

    return ret

  def _getJDLParameters(self, jdl):
    """Returns a dictionary of JDL parameters.
    """
    try:
      parameters = {}
#      print jdl
      if not re.search(r'\[', jdl):
        jdl = '[' + jdl + ']'
      classAdJob = ClassAd(jdl)
      paramsDict = classAdJob.contents
      for param, value in paramsDict.items():
        if value.strip().startswith('{'):
          self.log.debug('Found list type parameter %s' % (param))
          rawValues = value.replace('{', '').replace('}', '').replace('"', '').split()
          valueList = []
          for val in rawValues:
            if re.search(',$', val):
              valueList.append(val[:-1])
            else:
              valueList.append(val)
          parameters[param] = valueList
        else:
          parameters[param] = value.replace('"', '').replace('{', '"{').replace('}', '}"')
          self.log.debug('Found standard parameter %s: %s' % (param, parameters[param]))
      return S_OK(parameters)
    except Exception as x:
      self.log.exception(lException=x)
      return S_ERROR('Exception while extracting JDL parameters for job')

  def _saveJobJDLRequest(self, jobID, jobJDL):
    """Save job JDL local to JobAgent.
    """
    classAdJob = ClassAd(jobJDL)
    classAdJob.insertAttributeString('LocalCE', self.ceName)
    jdlFileName = jobID + '.jdl'
    jdlFile = open(jdlFileName, 'w')
    jdl = classAdJob.asJDL()
    jdlFile.write(jdl)
    jdlFile.close()

  def _extractValuesFromJobParams(self, params):
    """
    """
    submissionDict = {}

    submissionDict['jobID'] = params.get('JobID')
    if not submissionDict['jobID']:
      msg = 'Job has not JobID defined in JDL parameters'
      self._report(status='Failed', minor=msg)
      self.log.warn(msg)
      return self._finish('JDL Problem')

    submissionDict['jobType'] = params.get('JobType', 'Unknown')
    if submissionDict['jobType'] == 'Unknown':
      self.log.warn('Job has no JobType defined in JDL parameters')

    if 'CPUTime' not in params:
      self.log.warn('Job has no CPU requirement defined in JDL parameters')

    # Job requirements for determining the number of processors
    # the minimum number of processors requested
    submissionDict['processors'] = int(params.get('NumberOfProcessors', int(params.get('MinNumberOfProcessors', 1))))
    # the maximum number of processors allowed to the payload
    submissionDict['maxNumberOfProcessors'] = int(params.get('MaxNumberOfProcessors', 0))
    # need or not the whole node for the job
    submissionDict['wholeNode'] = 'WholeNode' in params
    submissionDict['mpTag'] = 'MultiProcessor' in params.get('Tags', [])

    if self.extraOptions and '$DIRACROOT' in params.get('Executable', '').strip():
      params['Arguments'] = (params.get('Arguments', '') + ' ' + self.extraOptions).strip()
      params['ExtraOptions'] = self.extraOptions

    return S_OK(submissionDict)

  def _report(self, jobID, status, minorStatus):
    """Wraps around setJobStatus of state update client
    """
    jobStatus = JobStateUpdateClient().setJobStatus(int(jobID), status, minorStatus, 'JobAgent@%s' % self.siteName)
    self.log.verbose('Setting job status',
                     'setJobStatus(%s,%s,%s,%s)' % (jobID, status, minorStatus, 'JobAgent@%s' % self.siteName))
    if not jobStatus['OK']:
      self.log.warn('Issue setting the job status', jobStatus['Message'])

    return jobStatus

  def _setJobParam(self, jobID, name, value):
    """Wraps around setJobParameter of state update client
    """
    jobParam = JobStateUpdateClient().setJobParameter(int(jobID), str(name), str(value))
    self.log.verbose('Setting job parameter',
                     'setJobParameter(%s,%s,%s)' % (jobID, name, value))
    if not jobParam['OK']:
      self.log.warn('Issue setting the job parameter', jobParam['Message'])

    return jobParam

  # --------------------------------------------------------------------------------------------------------------

  def _finish(self, message, stop=True):
    """Force the JobAgent to complete gracefully.
    """
    if stop:
      self.log.info('JobAgent will stop',
                    'with message "%s", execution complete.' % message)
      self.am_stopExecution()
      return S_ERROR(message)

    return S_OK(message)

  def _rescheduleFailedJob(self, jobID, message, stop=True):
    """
    Set Job Status to "Rescheduled" and issue a reschedule command to the Job Manager
    """

    self.log.warn('Failure ==> rescheduling',
                  '(during %s)' % (message))

    jobReport = JobReport(int(jobID), 'JobAgent@%s' % self.siteName)

    # Setting a job parameter does not help since the job will be rescheduled,
    # instead set the status with the cause and then another status showing the
    # reschedule operation.

    jobReport.setJobStatus(status='Rescheduled',
                           applicationStatus=message,
                           sendFlag=True)

    self.log.info('Job will be rescheduled')
    result = JobManagerClient().rescheduleJob(jobID)
    if not result['OK']:
      self.log.error('Failed to reschedule job', result['Message'])
      return self._finish('Problem Rescheduling Job', stop)

    self.log.info('Job Rescheduled', jobID)
    return self._finish('Job Rescheduled', stop)