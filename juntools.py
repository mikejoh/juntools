#!/usr/bin/env python

import pydot
import os
import re
import sys
from BeautifulSoup import BeautifulSoup

ERR = lambda msg: sys.stderr.write("ERR> " + str(msg) + "\n") or sys.exit(1)
DIRECTIONS = ['source','destination']

class jViz():
	def __init__(self,conffile,verbose=False):
		'''
		Initialize the jViz.

		@param string conffile: 	JunOS configuration file in XML format
		@param boolean verbose:		Be verbose, True or False
		'''

		self.cfile	= conffile
		self.zones	= []
		self.section	= []
		self.store 	= {}
		self.key	= {}
		self.polcount	= 0
		self.version	= None
		self.verbose	= verbose

	def cleanstring(self,string):
		'''
		Clean string from enclosing tags, returns the clean string.

		@param string string:		String enclosed in tags, e.g. <tag>string</tag>
		'''

		return re.sub('<[^>]*>', '', string)
	
	def parseconf(self,start,end):
		'''
		Parse the configuration and save the data inside start and end tags in a list. 
		This list is then made into a soup by BeautifulSoup. Returns the soup.
		
		@param string start:		Start tag, e.g. <policies>
		@param string end:		End tag, e.g. </policies>
		'''

		try:
			self.fh = open(self.cfile, 'r')
		except Exception, msg:
			ERR(msg)

		record = False

		for row in self.fh.readlines():
			row = row.strip()
			if '<version>' in row: # Always fetch the Juniper SRX version
				self.version = self.cleanstring(row)
			elif row == start: 	# Start tag
				record = True
			elif row == end: 	# End tag
				record = False

			if record == True:
				self.section.append(row)
			elif record == False:
				pass

		data = '\n'.join(self.section)
		self.soup = BeautifulSoup(data)
	
		return self.soup

	def getfwinfo(self):
		'''
		Outputs some more or less useful system information about the firewall(s).
		'''

		soup = self.parseconf('<system>','</system>')
		hostnames = soup.findAll('host-name')
		timezone = soup.find('time-zone').contents[0]
		for host in hostnames:
			print 'Hostname: ' + host.contents[0]
		print 'Timezone: ' + timezone
		print 'JunOS version: ' + self.version
		
	def getpolicies(self):
		'''
		Parses the soup made available from the parseconf method, sorts the firewall policies into a
		Pythonic form. Returns the parsed policies and a list of all available JunOS zones in the
		provided JunOS configuration.
		'''

		self.parseconf('<policies>','</policies>')

		recs = self.soup.findAll('policy')
	
		for rec in recs:
			if rec.find('from-zone-name'):
				self.key = (str(rec.find('from-zone-name').contents[0]), str(rec.find('to-zone-name').contents[0]))
			else:
				self.polcount += 1
				item = {}
				item['name'] = str(rec.find('name').contents[0])
				item['source-address'] = str(rec.find('match').find('source-address').contents[0])
				item['destination-address'] = str(rec.find('match').find('destination-address').contents[0])
				item['application'] = str(rec.find('match').find('application').contents[0])
				if self.store.has_key(self.key):
					self.store[self.key].append(item)
				else:
					self.store[self.key] = [item]

		for k,v in self.store.iteritems():
			if '*' in k[0] or '*' in k[1]:
				pass
			elif k[0] not in self.zones:
				self.zones.append(k[0])
			elif k[1] not in self.zones:
				self.zones.append(k[1])
			else:
				pass

		return self.store, self.zones

	def creategraph(self,zone,direction,gdir='/root/bin/gviz/graphs/'):
		'''
		Creates one graph based on zone and direction of the relations. The graph is created by pydot,
		a Python API to the dot-language.

		@param string zone:		A zone that is available in the JunOS configuration
		@param string direction:	The direction of the relations drawn in the graph, source or destination
		@param string gdir:		Directory to save the graphs, default is /root/bin/gviz/graphs/
		'''

		if direction not in DIRECTIONS:
			ERR('The direction: ' + direction + ' is not valid!')
		if zone not in self.zones:
			ERR('The zone: ' + zone + ' is not valid!')	

		graph = pydot.Dot(graph_type='digraph')
		count = 0

		for k,v in self.store.iteritems():
			source = k[0]
			dest = k[1]
			srcnode = pydot.Node(source, style="filled", fillcolor='red')
			destnode = pydot.Node(dest, style="filled", fillcolor='green')
			if source == zone and direction == 'source' and self.verbose == True:
				print source + '\t\t-->\t' + dest + ' has ' + str(len(v)) + ' policies.'
				count += len(v)
			elif dest == zone and direction == 'destination' and self.verbose == True:
				print dest + '\t\t<--\t' + source + ' has ' + str(len(v)) + ' policies.'
				count += len(v)

			for num in range(0, len(v)):
				name = v[num]['name']
				app = v[num]['application']
				if direction == 'source' and source == zone:
					graph.add_node(srcnode)
					graph.add_node(destnode)
					graph.add_edge(pydot.Edge(source, dest, label=app, color='red'))
				elif direction == 'destination' and dest == zone:
					graph.add_node(srcnode)
					graph.add_node(destnode)
					graph.add_edge(pydot.Edge(source, dest, label=app, color='red'))
	
		directory = gdir
		graphfile = 'FW_graph_' + zone + '_' + direction + '.png'
		graph.write_png(directory + graphfile)
		if self.verbose == True:
			filesize = os.path.getsize(directory + graphfile)
			print 'Total policies:\t' + str(count)
			print 'Created:\t' + graphfile + ' in ' + directory
			print 'File size:\t' + str(filesize) + ' bytes'

	def closeconf(self):
		'''
		Closes the opened filehandle, if it exists.
		'''

		try:
			if self.fh:
				self.fh.close()
		except:
			ERR('Nothing open!')
