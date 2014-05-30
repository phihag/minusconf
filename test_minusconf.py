#!/usr/bin/env python
"""Apache License 2.0, see the LICENSE file for details."""

import unittest
import minusconf
import socket
import time
import os

class MinusconfUnitTest(unittest.TestCase):
	def setUp(self):
		try:
			self._sharp_s = unichr(223)
		except: # Python 3+
			self._sharp_s = chr(223)
		sz = self._sharp_s
		
		self._testid = socket.gethostname() + str(os.getpid())
		self.svc1 = minusconf.Service('-conf-test-service-strange-' + self._testid, 'strangeport' + sz, 'some name' + sz, 'loc: ' + sz)
		self.svc2 = minusconf.Service('-conf-test-service' + sz + '-' + self._testid, 'strangeport', 'some name', 'some location')
		self.svc3 = minusconf.Service('-conf-test-service' + sz + '-' + self._testid, 'svcp3', 'svc3: sharp s = ' + sz)
		self.svc4 = minusconf.Service('-conf-test-service' + sz + '-' + self._testid, 'svcp4', 'svc4', 'Buy More basement')
		self.svc5 = minusconf.Service('-conf-test-service' + sz + '-' + self._testid, 'svcp5', 'svc5')
	
	def testServiceMatching(self):
		a = minusconf.Advertiser()
		def assert_sm(stype, sname, expected):
			self.assertEquals(set(a.services_matching(stype, sname)), set(expected))
		
		assert_sm('', '', [])
		
		a.services.append(self.svc1)
		assert_sm(self.svc1.stype, self.svc1.sname, [self.svc1])
		assert_sm(self.svc1.stype, '', [self.svc1])
		
		a.services.append(self.svc2)
		assert_sm(self.svc2.stype, self.svc2.sname, [self.svc2])
		
		a.services.append(self.svc3)
		assert_sm(self.svc3.stype, self.svc3.sname, [self.svc3])
		assert_sm('', self.svc3.sname, [self.svc3])
		
		assert_sm('', '', [self.svc1, self.svc2, self.svc3])
	
	def testServiceRepresentation(self):
		svca = minusconf.ServiceAt('aaa', 'bbb', 'ccc', 'ddd', 'eee', 'fff')
		
		reprfuncs = [repr]
		try:
			if not callable(unicode):
				raise Exception
			
			reprfuncs.append(unicode)
		except:
			reprfuncs.append(str) # Python 3+: str does not step over Unicode chars anymore
		
		for reprfunc in reprfuncs:
			for svc in [self.svc1, self.svc2, self.svc3, self.svc4, svca]:
				r = reprfunc(svc)
				self.assertTrue(r.find(reprfunc(svc.stype)) >= 0)
				self.assertTrue(r.find(reprfunc(svc.port)) >= 0)
				self.assertTrue(r.find(reprfunc(svc.sname)) >= 0)
			
			r = reprfunc(svca)
			self.assertTrue(r.find(reprfunc(svca.aname)) >= 0)
			self.assertTrue(r.find(reprfunc(svca.location)) >= 0)
	
	def testSingleThreadAdvertiser(self):
		a_thread = minusconf.ThreadAdvertiser([], 'unittest.advertiser-thread-single')
		self._runSingleConcurrentAdvertiserTest(a_thread)
	
	if hasattr(minusconf, 'MultiprocessingAdvertiser'):
		def testSingleMultiprocessingAdvertiser(self):
			a_mp = minusconf.MultiprocessingAdvertiser([], 'unittest.advertiser-multiprocessing-single')
			self._runSingleConcurrentAdvertiserTest(a_mp)
		
		def testMultiMultiprocessingAdvertisers(self):
			a1 = minusconf.MultiprocessingAdvertiser([], 'unittest.multitest.MultiprocessingAdvertiser1')
			a2 = minusconf.MultiprocessingAdvertiser([], 'unittest.multitest.MultiprocessingAdvertiser2')
			
			self._runMultiTest([
				(a1, [self.svc1, self.svc2, self.svc3]),
				(a2, [self.svc3, self.svc4, self.svc5]),
				], self.svc2.stype)
		
		def testMultiCombinedAdvertisers(self):
			mpa1 = minusconf.MultiprocessingAdvertiser([], 'unittest.multictest.MultiprocessingAdvertiser1')
			mpa2 = minusconf.MultiprocessingAdvertiser([], 'unittest.multictest.MultiprocessingAdvertiser2')
			ta1 = minusconf.ThreadAdvertiser([], 'unittest.multictest.ThreadAdvertiser1')
			ta2 = minusconf.ThreadAdvertiser([], 'unittest.multictest.ThreadAdvertiser2')
			ta3 = minusconf.ThreadAdvertiser([], 'unittest.multictest.ThreadAdvertiser3')
			
			self._runMultiTest([
				(mpa1, [self.svc1, self.svc2, self.svc3]),
				(mpa2, [self.svc3]),
				(ta1, [self.svc2, self.svc4]),
				(ta2, [self.svc1, self.svc5]),
				(ta3, []),
				], self.svc2.stype)
	
	def testMultiThreadAdvertisers(self):
		a1 = minusconf.ThreadAdvertiser([], 'unittest.multitest.ThreadAdvertiser1')
		a2 = minusconf.ThreadAdvertiser([], 'unittest.multitest.ThreadAdvertiser2')
		
		self._runMultiTest([
			(a1, [self.svc1, self.svc2, self.svc3]),
			(a2, [self.svc3, self.svc4, self.svc5]),
			], self.svc2.stype)
	
	def testInetPton(self):
		bts = minusconf._compat_bytes
		testVals = [
			(socket.AF_INET, '1.2.3.4', bts('\x01\x02\x03\x04')),
			(socket.AF_INET, '255.254.253.252', bts('\xff\xfe\xfd\xfc')),
			(socket.AF_INET6, '::', bts('\x00')*16),
			(socket.AF_INET6, '::1', bts('\x00')*15 + bts('\x01')),
			(socket.AF_INET6, '100::', bts('\x01') + bts('\x00')*15),
			(socket.AF_INET6, '0100::', bts('\x01') + bts('\x00')*15),
			(socket.AF_INET6, '1000::', bts('\x10') + bts('\x00')*15),
			(socket.AF_INET6, 'ff25::12:2:254.232.3.4', bts('\xff\x25\x00\x00\x00\x00\x00\x00\x00\x12\x00\x02\xfe\xe8\x03\x04')),
			(socket.AF_INET6, 'ffff:2:3:4:ffff::', bts('\xff\xff\x00\x02\x00\x03\x00\x04\xff\xff') + bts('\x00') * 6),
			]
		
		invalidVals = [
			(socket.AF_INET, '1.2.3'),
        		(socket.AF_INET, '1.2.3.4.5'),
			(socket.AF_INET, '301.2.2.2'),
			(socket.AF_INET, '::1.2.2.2'),
			(socket.AF_INET6, '1:2:3:4:5:6:7'),
			(socket.AF_INET6, '1:2:3:4:5:6:7:'),
			(socket.AF_INET6, ':2:3:4:5:6:7:8'),
			(socket.AF_INET6, '1:2:3:4:5:6:7:8:9'),
			(socket.AF_INET6, '1:2:3:4:5:6:7:8:'),
			(socket.AF_INET6, '1::3:4:5:6::8'),
			(socket.AF_INET6, 'a:'),
			(socket.AF_INET6, ':'),
			(socket.AF_INET6, ':::'),
			(socket.AF_INET6, '::a:'),
			(socket.AF_INET6, ':a::'),
			(socket.AF_INET6, '1ffff::'),
			(socket.AF_INET6, '0xa::'),
			(socket.AF_INET6, '1:2:3:4:5:6:300.2.3.4'),
			(socket.AF_INET6, '1:2:3:4:5:6:1a.2.3.4'),
			(socket.AF_INET6, '1:2:3:4:5:1.2.3.4:8'),
			]
		
		for ptonf in (minusconf._inet_pton, minusconf._compat_inet_pton):
			for (family, arg, expected) in testVals:
				self.assertEquals(ptonf(family, arg), expected)
			
			for (family, arg) in invalidVals:
				self.assertRaises((ValueError, socket.error), ptonf, family, arg)
	
	def testResolveAddrs(self):
		ra = minusconf._resolve_addrs
		def testResolveTo(rares, expected_addr, fam=socket.AF_INET):
			fr = rares[0] # first result
			self.assertEquals(fam, fr[0])
			self.assertEquals(minusconf._inet_pton(fam, fr[1][0]), minusconf._inet_pton(fam, expected_addr))
		
		# Test auto conversion
		if MinusconfUnitTest._IPv6supported():
			testResolveTo(ra(['1.2.3.4'], None, False, [socket.AF_INET6]), '::ffff:1.2.3.4', socket.AF_INET6)
		testResolveTo(ra(['1.2.3.4'], None, False, [socket.AF_INET]), '1.2.3.4')
		
		# These are so long to prevent them from being resolved (which really slows down systems trying to contact an unreachable DNS server)
		invalid = ['::1::..invalid_address'*256, '::1::..invalid_address_2'*256]
		self.assertRaises(socket.gaierror, ra, [invalid[0]], None, False)
		self.assertEquals(ra([invalid[0], '1.2.3.4', invalid[1]], None, True), [(socket.AF_INET, ('1.2.3.4', 0), socket.AF_INET, '1.2.3.4')])
	
	def testNUL(self):
		optlen = 4
		for i in range(optlen):
			toptions = ['x'] * optlen
			toptions[i] = 'null\x00byte'
			
			self.assertRaises(ValueError, minusconf.Service, *toptions)
		
		optlen = 3
		for i in range(optlen):
			toptions = ['x'] * optlen
			toptions[i] = 'null\x00byte'
			
			self.assertRaises(ValueError, minusconf.Seeker, *toptions)
		
		self.assertRaises(ValueError, minusconf.Advertiser, [], 'advertiser\x00name')
	
	def testIntPort(self):
		svc = minusconf.Service('stype', 42, 'sname')
		x = 'a' + self._sharp_s + str(svc) + repr(svc)
	
	def testSeekerSanity(self):
		stype = 'stype ' + self._sharp_s
		aname = 'aname ' + self._sharp_s
		sname = 'sname ' + self._sharp_s + ' (wienerlicious)'
		s = minusconf.Seeker(stype, aname, sname)
		
		self.assertEquals(s.stype, stype)
		self.assertEquals(s.aname, aname)
		self.assertEquals(s.sname, sname)
		
		s.stype = stype
		s.aname = aname
		s.sname = sname
		
		self.assertEquals(s.stype, stype)
		self.assertEquals(s.aname, aname)
		self.assertEquals(s.sname, sname)
		
		s.timeout = 0.00001
		s.run() # Shouldn't find anything
		s._found_result(minusconf.ServiceAt('aaa', 'bbb', 'ccc', 'ddd', 'eee', 'fff'))
		s.run() # dito
		
		self.assertTrue(len(s.results) == 0)
	
	def testMalformed(self):
		_cb = minusconf._compat_bytes
		
		## Packets to the advertiser
		a = minusconf.Advertiser([self.svc2], 'minusconf.test.malformed.' + self._testid)
		a._sock = self._create_fake_sock()
		
		avsend = lambda data: a._handle_packet(data, '::')
		sendquery = lambda data: avsend(minusconf._MAGIC + minusconf._OPCODE_QUERY + data)
		
		# Invalid magic
		avsend(_cb(''))
		avsend(_cb('X'))
		avsend(_cb('bye'))
		avsend(_cb('hell'))
		avsend(_cb('hello'))
		avsend(_cb('hello minusconf'))
		
		# Invalid opcode
		avsend(minusconf._MAGIC)
		avsend(minusconf._MAGIC + _cb('\x00'))
		avsend(minusconf._MAGIC + _cb('\xff'))
		
		# Advertiser-to-seeker opcode
		avsend(minusconf._MAGIC + minusconf._OPCODE_ADVERTISEMENT)
		avsend(minusconf._MAGIC + minusconf._OPCODE_ERROR + _cb('s\0'))
		
		# Invalid query
		sendquery(_cb(''))
		sendquery(_cb('\0\0'))
		
		# Valid query with more data
		sendquery(_cb('a\0b\0c\0d'))
		sendquery(_cb('a\0b\0c\0d\0'))
		sendquery(_cb('a\0b\0c\0'))
		
		# Invalid UTF-8
		sendquery(_cb('\xff\0\xff\0\xff\0'))
		
		
		## Packets to the seeker
		s = minusconf.Seeker()
		s._init_seeker()
		
		sksend = lambda data: s._handle_packet(data, '::')
		skav = lambda data: sksend(minusconf._MAGIC + minusconf._OPCODE_ADVERTISEMENT + data)
		
		# Invalid magic
		sksend(_cb(''))
		sksend(_cb('X'))
		sksend(_cb('bye'))
		sksend(_cb('hell'))
		sksend(_cb('hello'))
		sksend(_cb('hello minusconf'))
		
		# Invalid opcode
		sksend(minusconf._MAGIC)
		sksend(minusconf._MAGIC + _cb('\x00'))
		sksend(minusconf._MAGIC + _cb('\xff'))

		# Advertiser-to-seeker opcode
		sksend(minusconf._MAGIC + minusconf._OPCODE_QUERY + _cb('\0\0\0'))
		
		# Invalid advertisement
		skav(_cb(''))
		skav(_cb('\0'))
		skav(_cb('\0\0\0\0'))
		skav(_cb('a\0b\0c\0d\0'))
		
		# Invalid UTF-8
		skav(_cb('aname-utf\xff\0stype\0sname\0loc\0port\0'))
		
		# Nearly valid advertisements
		skav(_cb('aname-nostype\0\0sname\0loc\0port\0')) # no servicetype
		s.aname = 'asdf'
		skav(_cb('aname-notaskedfor\0\0sname\0loc\0port\0')) # not asked for
		
		self.assertTrue(len(s.results) == 0)
		
		# Additional data
		s.aname = ''
		skav(_cb('aname\0stype\0sname\0loc\0port\0additional data'))
		
		self.assertTrue(len(s.results) == 1)
	
	def _runSingleConcurrentAdvertiserTest(self, advertiser):
		advertiser.start_blocking()
		
		advertiser.services.append(self.svc1)
		self._runTestSeek([self.svc1], self.svc1.stype)
		
		advertiser.services.append(self.svc2)
		self._runTestSeek([self.svc1], self.svc1.stype)
		self._runTestSeek([self.svc2], self.svc2.stype)
		
		advertiser.services.append(self.svc3)
		self.assertEquals(self.svc2.stype, self.svc3.stype)
		self._runTestSeek([self.svc1], self.svc1.stype)
		self._runTestSeek([self.svc2, self.svc3], self.svc2.stype)
		
		advertiser.stop_blocking()
		
		self._runTestSeek([], self.svc2.stype)
	
	def _runTestSeek(self, services, stype=None, timeouts=[0.01,0.1,0.5]):
		if stype == None:
			if len(services) > 0:
				stype = services[0].stype
			else:
				stype = ''
		
		s = minusconf.Seeker(stype)
		svc_eq = lambda svc, exp: (svc.sname == exp.sname and svc.stype == exp.stype and svc.port == exp.port)
		svc_in = lambda svc, svcs: any((svc_eq(svc, s) for s in svcs))
		def find_callback(seeker,svcat):
			if not svc_in(svcat, services):
				raise AssertionError('Got ' + repr(svcat) + ', expected one of ' + repr(services))
			self.assertTrue(svcat.aname != '')
		s.find_callback = find_callback
		s.error_callback = lambda seeker,serveraddr,errorstr: self.fail('Got error ' + repr(errorstr) + ' from ' + repr(serveraddr))
		
		if len(services) == 0:
			timeouts = [max(timeouts)]
		
		for to in timeouts:
			try:
				s.timeout = to
				s.run()
				
				for svc in services:
					if not svc_in(svc, s.results):
						raise AssertionError('Missing ' + repr(svc) + ', got ' + repr(s.results))
				
				break
			except AssertionError:
				if to == max(timeouts):
					raise
		
		return s.results
	
	def _runMultiTest(self, advertiser_services, stype):
		try:
			for av,svcs in advertiser_services:
				av.start_blocking()
			
			expected_services = set()
			for av,svcs in advertiser_services:
				av.services += svcs
				expected_services.update(filter(lambda svc: svc.stype == stype, svcs))
			
			self._runTestSeek(expected_services, stype)
			
			for av,svcs in advertiser_services:
				av.stop_blocking()
			
			self._runTestSeek([], stype)
		finally:
			for av,svcs in advertiser_services:
				try:
					av.stop_blocking()
				except:
					pass
	
	def _create_fake_sock(self):
		class _FakeSocket(object):
			def sendto (sockself, data, flags, to):
				pass
		
		return _FakeSocket()
	
	@staticmethod
	def _IPv6supported():
		if not socket.has_ipv6:
			return False
		
		try:
			socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
		except socket.gaierror:
			return False
		
		return True

if __name__ == '__main__':
	unittest.main()
