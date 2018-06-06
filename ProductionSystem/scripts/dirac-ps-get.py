#!/usr/bin/env python

"""
  Get production parameters
"""

__RCSID__ = "$Id$"

import DIRAC
from DIRAC.Core.Base import Script
from DIRAC.Core.Utilities.PrettyPrint import printTable

Script.setUsageMessage( '\n'.join( [ __doc__.split( '\n' )[1],
                                     'Usage:',
                                     '  %s prodID' % Script.scriptName,
                                     'Arguments:',
                                     '  prodID: Production ID'
                                     ] ) )


Script.parseCommandLine()

from DIRAC.ProductionSystem.Client.ProductionClient import ProductionClient

prodClient = ProductionClient()

# get arguments
args = Script.getPositionalArgs()
if ( len( args ) > 1 ):
  Script.showHelp()
elif ( len( args ) == 1 ):
  prodID = args[0]
  res = prodClient.getProduction(prodID)
else:
  res = prodClient.getProductions()

fields = ['ProductionID','ProductionName', 'Description', 'Status', 'CreationDate','LastUpdate','AuthorDN','AuthorGroup']
records = []

if res['OK']:
  prodList = res['Value']
  if not isinstance(res['Value'], list):
    prodList = [res['Value']]
  for prod in prodList:
    records.append( [str(prod['ProductionID']), str(prod['ProductionName']), str(prod['Description']), str(prod['Status']), \
                     str(prod['CreationDate']), str(prod['LastUpdate']), str(prod['AuthorDN']), \
                     str(prod['AuthorGroup'])] )
else:
  DIRAC.gLogger.error ( res['Message'] )
  DIRAC.exit( -1 )

printTable( fields, records )

DIRAC.exit( 0 )


