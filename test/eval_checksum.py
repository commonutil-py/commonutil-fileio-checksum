#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import logging
from zlib import adler32

from commonutil_fileio_checksum import b64digest
from commonutil_fileio_checksum import checksum
from commonutil_fileio_checksum import md5sum, sha256sum, sha512sum

_log = logging.getLogger(__name__)


class Adler32Hasher:
	def __init__(self):
		self.value = 1

	def update(self, b):
		self.value = adler32(b, self.value)

	def digest(self):
		return self.value.to_bytes(4, 'big')

	def hexdigest(self):
		return self.digest().hex()


def log_checksum(checksum_name, h_obj):
	_log.info("> %s", checksum_name)
	_log.info("> (Hex): %r", h_obj.hexdigest())
	_log.info("> (B64): %r", b64digest(h_obj))


def run_packed_checksum(file_path, checksum_callable, checksum_name):
	h_obj = checksum_callable(file_path)
	log_checksum(checksum_name, h_obj)


def run_custom_checksum(file_path, hash_object, checksum_name):
	h_obj = checksum(file_path, hash_object)
	log_checksum(checksum_name, h_obj)


def main():
	logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
	for file_path in sys.argv[1:]:
		_log.info("File: %r", file_path)
		run_packed_checksum(file_path, md5sum, "MD5")
		run_packed_checksum(file_path, sha256sum, "SHA-256")
		run_packed_checksum(file_path, sha512sum, "SHA-512")
		run_custom_checksum(file_path, Adler32Hasher(), "Adler32")


if __name__ == "__main__":
	sys.exit(main())
