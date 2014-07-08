#!/usr/bin/env python
#@author: Prahlad Yeri
#@description: Small daemon to create a wifi hotspot on linux
#@license: MIT
import os
import sys

#INSTALL IT
from distutils.core import setup
s = setup(name='hotspotd',
	version='0.1',
	description='Small daemon to create a wifi hotspot on linux',
	license='MIT',
	author='Prahlad Yeri',
	author_email='prahladyeri@yahoo.com',
	url='https://github.com/prahladyeri/hotspotd',
	#py_modules=['hotspotd','cli'],
	packages=['hotspotd'],
	package_dir={'hotspotd': ''},
	package_data={'hotspotd': ['run.dat']},
	#data_files=[('config',['run.dat'])],
	)
	

if 'install' in sys.argv:
	pkk = 'site-packages'
	#NOTE: sys.prefix doesn't equate to /usr/local for some reason
	loc=os.sep.join(['/usr/local', 'lib', 'python' + sys.version[:3], 'site-packages'])
	if not os.path.exists(loc+'/hotspotd'):
		loc=os.sep.join(['/usr/local', 'lib', 'python' + sys.version[:3], 'dist-packages'])
	
	for i in range(len(sys.argv)):
		s = sys.argv[i]
		if '--prefix=' in s:
			s=s.replace('--prefix=','').strip()
			loc=os.sep.join([s, 'lib', 'python' + sys.version[:3], 'site-packages'])
			if not os.path.exists(loc+'/hotspotd'):
				loc=os.sep.join([s, 'lib', 'python' + sys.version[:3], 'dist-packages'])
		elif s.strip()=='--prefix':
			n=i+1
			if n<=len(sys.argv):
				s = sys.argv[n]
				loc=os.sep.join([s, 'lib', 'python' + sys.version[:3], 'site-packages'])
				if not os.path.exists(loc+'/hotspotd'):
					loc=os.sep.join([s, 'lib', 'python' + sys.version[:3], 'dist-packages'])
	print 'Install base: ' + loc

	import distutils
	distutils.file_util.copy_file(loc + '/hotspotd/hotspotd.py','/usr/bin/hotspotd',link='sym',preserve_mode=1)
	os.chmod(loc + '/hotspotd/hotspotd.py',0755)
	#print distutils.sysconfig.PREFIX
	#print distutils.sysconfig.get_python_lib()
	#~ import hotspotd
	#~ print os.getcwd()
	#~ print hotspotd.__file__
	#~ print os.path.dirname(hotspotd.__file__)
	#~ print s
	#~ print ''
	#~ loc=''
	#~ if '--prefix' in sys.argv:
		#~ loc=os.sep.join([sys.argv['prefix'], 'lib', 'python' + sys.version[:3], 'site-packages'])
	#~ else:
		#~ loc=os.sep.join([sys.prefix, 'lib', 'python' + sys.version[:3], 'site-packages'])
	#~ print loc
	#distutils.file_util.copy_file('hotspotd.py','testo.py')
