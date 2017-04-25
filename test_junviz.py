#!/usr/bin/env python

import sys
from juntools import jViz

zone 		= sys.argv[1]
direction 	= sys.argv[2]

viz = jViz('juniperconf_xml_2012_07_26.txt',verbose=True)

#viz.parseconf('<policies>','</policies>')
policies, zones = viz.getpolicies()
viz.creategraph(zone,direction,gdir='/root/bin/gviz/')

#viz.getfwinfo()
viz.closeconf()

print 'Done!'
