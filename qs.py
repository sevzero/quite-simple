#!/usr/bin/env python

import random
import sys
import os
import time
import io
import binascii
import re
import zlib
import itertools
import base64
import hashlib
from threading import Thread

args = None
chunksize = 4096 # Must be even

calls = [i.strip() for i in ' '.join(sys.argv[1:]).split(':') if i]

def encode_base64(inpipe, outpipe, opts=[]):
	base64.encode(inpipe, outpipe)

def encode_hex(inpipe, outpipe, opts=[]):
	o = inpipe.read(chunksize)
	while len(o):
		outpipe.write(binascii.hexlify(o))
		o = inpipe.read(chunksize)

def decode_hex(inpipe, outpipe, opts=[]):
	o = inpipe.read(chunksize)
	while len(o):
		outpipe.write(binascii.unhexlify(o.strip().replace(' ', '')))
		o = inpipe.read(chunksize)

def decode_base64(inpipe, outpipe, opts=[]):
	base64.decode(inpipe, outpipe)

def hash_md5(inpipe, outpipe, opts=[]):
	_run_hash(hashlib.md5(), inpipe, outpipe, opts)

def hash_sha1(inpipe, outpipe, opts=[]):
	_run_hash(hashlib.sha1(), inpipe, outpipe, opts)

def hash_sha224(inpipe, outpipe, opts=[]):
	_run_hash(hashlib.sha224(), inpipe, outpipe, opts)

def hash_sha256(inpipe, outpipe, opts=[]):
	_run_hash(hashlib.sha256(), inpipe, outpipe, opts)

def hash_sha384(inpipe, outpipe, opts=[]):
	_run_hash(hashlib.sha384(), inpipe, outpipe, opts)

def hash_sha512(inpipe, outpipe, opts=[]):
	_run_hash(hashlib.sha512(), inpipe, outpipe, opts)

def bitwise_xor(inpipe, outpipe, opts=[]):
	for i, b in enumerate(opts):
		try:
			#TODO: Could be > 255
			opts[i] = chr(int(b, 16))
		except ValueError:
			continue
	key = bytearray(''.join(opts))
	rotator = rotate_through(key)
	o = bytearray(inpipe.read(chunksize))
	while o:
		for i in xrange(len(o)):
			o[i] = (chr(o[i] ^ rotator.next()))
		outpipe.write(o)
		o = bytearray(inpipe.read(chunksize))

def text_upper(inpipe, outpipe, args=[]):
	o = inpipe.read(chunksize)
	while o:
		o = o.upper()
		outpipe.write(o)
		o = inpipe.read(chunksize)

def text_lower(inpipe, outpipe, args=[]):
	o = inpipe.read(chunksize)
	while o:
		o = o.lower()
		outpipe.write(o)
		o = inpipe.read(chunksize)

def code_number(inpipe, outpipe, args=[]):
	for i, line in enumerate(inpipe):
		outpipe.write('%d %s' % (i+1, line))

def compress_gzip(inpipe, outpipe, args=[]):
	#TODO: Add support for compression level
	encoder = zlib.compressobj(-1, zlib.DEFLATED, zlib.MAX_WBITS | 16)
	o = inpipe.read(chunksize)
	while o:
		outpipe.write(encoder.compress(o))
		o = inpipe.read(chunksize)
	outpipe.write(encoder.flush())

def deflate_gzip(inpipe, outpipe, args=[]):
	decoder = zlib.decompressobj(zlib.MAX_WBITS|16)
	o = inpipe.read(chunksize)
	while o:
		outpipe.write(decoder.decompress(o))
		o = inpipe.read(chunksize)

def http_headers(inpipe, outpipe, args=[]):
	for l in inpipe:
		if not l.strip(): break
		outpipe.write(l)

def http_header(inpipe, outpipe, args=[]):
	#TODO: Error handling
	hdr_search = args[0]
	for l in inpipe:
		if not ': ' in l: continue
		hdr_name = l.split(': ')[0]
		if hdr_name == hdr_search:
			outpipe.write(':'.join(l.split(': ')[1:]))
			return

def http_body(inpipe, outpipe, args=[]):
	o = inpipe.readline()
	while True:
		if not len(o.strip()):
			break
		o = inpipe.readline()
	_buffered_transfer(inpipe, outpipe)

def http_content(inpipe, outpipe, args=[]):
	o = inpipe.readline()
	while True:
		if not len(o.strip()):
			break
		o = inpipe.readline()
	_buffered_transfer(inpipe, outpipe)

def http_request(inpipe, outpipe, args=[]):
	try:
		requested_index = int(args[0]) if args else 0
	except ValueError:
		requested_index = 0
	request_search = re.compile(r'^(GET|POST|HEAD|PUT|OPTIONS) .* HTTP/.*$')
	content_length = None
	for i in xrange(requested_index+1):
		o = _skip_to_line(request_search, inpipe)
	while True:
		if not len(o.strip()):
			break
		if o.startswith('Content-Length') and ':' in o:
			try:
				content_length = int(o.split(':')[1].strip())
			except ValueError:
				pass
		outpipe.write(o)
		o = inpipe.readline()
	if content_length:
		_buffered_transfer(inpipe, outpipe, bytes=content_length, chunksize=chunksize)

def http_response(inpipe, outpipe, args=[]):
	#TODO: Fix for HTTP chunked encoding
	try:
		requested_index = int(args[0]) if args else 0
	except ValueError:
		requested_index = 0
	index = 0
	content_length = None
	for i in xrange(requested_index+1):
		o = _skip_to_line('HTTP/', inpipe)
	while True:
		outpipe.write(o)
		if not len(o.strip()):
			break
		if o.startswith('Content-Length') and ':' in o:
			try:
				content_length = int(o.split(':')[1].strip())
			except ValueError:
				pass
		o = inpipe.readline()
	_buffered_transfer(inpipe, outpipe, bytes=content_length, chunksize=chunksize)

# Utils

def _buffered_transfer(inpipe, outpipe, bytes=None, chunksize=4096):
	remainder = None
	if bytes:
		chunks = bytes/chunksize
		remainder = bytes % chunksize
	for chunk in xrange(chunks) if bytes else itertools.count():
		data = inpipe.read(chunksize)
		if not data:
			return
		outpipe.write(data)
	if remainder:
		outpipe.write(inpipe.read(remainder))


def _skip_to_header(search, pipe):
	o = pipe.readline()
	while True:
		if o.startswith(search) and ':' in o or not len(o.strip()):
			return o.split(':')[1] if o else o
		o = pipe.readline()

def _skip_to_line(search, pipe):
	regex = hasattr(search, 'match')
	o = pipe.readline()
	while True:
		if (search.match(o) if regex else o.startswith(search)) or not len(o):
			return o
		o = pipe.readline()

def _run_hash(h, inpipe, outpipe, args=[]):
	o = inpipe.read(chunksize)
	while o:
		h.update(o)
		o = inpipe.read(chunksize)
	outpipe.write(h.hexdigest())

def rotate_through(array):
	i = 0
	l = len(array)
	while True:
		yield array[i]
		if i == l:
			i = 0

QS = {
	'encode': {
		'base64': encode_base64,
		'hex': encode_hex,
	},
	'decode': {
		'base64': decode_base64,
		'hex': decode_hex,
	},
	'hash': {
		'md5': hash_md5,
		'sha1': hash_sha1,
		'sha224': hash_sha224,
		'sha256': hash_sha256,
		'sha384': hash_sha384,
		'sha512': hash_sha512,
	},
	'bitwise': {
		'xor': bitwise_xor,
	},
	'text': {
		'upper': text_upper,
		'lower': text_lower,
	},
	'code': {
		'number': code_number,
	},
	'compress': {
		'gzip': compress_gzip,
	},
	'deflate': {
		'gzip': deflate_gzip,
	},
	'http': {
		'headers': http_headers,
		'header': http_header,
		'request': http_request,
		'content': http_content,
		'body': http_body,
		'response': http_response,
	},
}

if __name__ == '__main__':
	func = QS
	pipes = [os.pipe()]
	threads = []
	t = Thread(target=_buffered_transfer, args=(os.fdopen(sys.stdin.fileno(), 'rb', 0), os.fdopen(pipes[-1][1], 'wb', 0)))
	threads.append(t)
	t.start()
	for call in calls:
		cmd = call.split(' ')[0]
		args = call.split(' ')[1:]
		for part in cmd.split('.'):
			try:
				func = func[part]
			except KeyError:
				sys.stderr.write('Unknown operation %s\n') % '.'.join(cmd)
		if callable(func):
			pipe = os.pipe()
			t = Thread(target=func, args=(os.fdopen(pipes[-1][0], 'rb', 0), os.fdopen(pipe[1], 'wb', 0), args))
			pipes.append(pipe)
			threads.append(t)
			t.start()
			func = QS
	t = Thread(target=_buffered_transfer, args=(os.fdopen(pipes[-1][0], 'rb'), sys.stdout))
	t.start()
