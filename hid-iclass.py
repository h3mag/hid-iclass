#!/usr/bin/env python
#
# Papers used:
# (1) Heart of Darkness - exploring the uncharted backwaters of HID iCLASS security
# (2) Dismantling iClass and iClass Elite
#
import argparse
import os
import sys

from Crypto.Cipher import DES


"""
From Definition 10 in (2)
"""
PI = [ 0x0F, 0x17, 0x1B, 0x1D, 0x1E, 0x27, 0x2B, 0x2D, 0x2E, 0x33, 0x35, 0x39, 0x36, 0x3A, 0x3C, 0x47, 0x4B, 0x4D, 0x4E, 0x53, 0x55, 0x56, 0x59, 0x5A, 0x5C, 0x63, 0x65, 0x66, 0x69, 0x6A, 0x6C, 0x71, 0x72, 0x74, 0x78 ]


def byte_array_to_string(ba):
	"""
	Helper method to convert a byte array to hex string.
	"""
	return ''.join(map(chr, ba)).encode('hex')


def reverse_permute(key):
	n = 3

	while n > 0:
		tkey = [0] * 8
		n -= 1

		for i in range(8):
			p = 0
			mask = 0x80 >> i

			for x in range(8):
				p >>= 1

				if key[x] & mask:
					p |= 0x80
			tkey[i] = p
		key = tkey

	return key


def shave(key):
	return map(lambda k: k & 0xfe, key)


def reverse_permute_and_shave(key):
	"""
	From Appendix C-B in (1)
	"""
	key = reverse_permute(key)
	return shave(key)


def unpack(bytez):
	"""
	Helper method to unpack a byte array into x, y, z
	x, y are 8 bits each
	z is an array of dim 8 with 6 bits per member
	"""
	v = int(bytez.encode('hex'), 16)
	x = 0
	y = 0
	z = [0] * 8

	for i in range(8):
		z[i] = v & 0x3f
		v >>= 6

	y = v & 0xff
	v >>= 8
	x = v & 0xff

	return x, y, z


def ck(i, j, z):
	if (i == 1) and (j == -1):
		return z

	if (j == -1):
		return ck(i - 1, i - 2, z)
	
	if z[i] == z[j]:
		z[i] = j

	return ck(i, j - 1, z)


def check(zs):
	"""
	From Definition 8 in (2)
	"""
	zc1 = ck(3, 2, zs[0:4])
	zc2 = ck(3, 2, zs[4:8])
	zc = zc1 + zc2

	return zc


def permute(p, z, l, r):
	"""
	From Definition 9 in (2)
	"""
	rlp = len(p)
	if rlp == 0:
		return []

	lp = rlp - 1
	if p[lp] == '1':
		return [(z[l] + 1) & 0x3f] + permute(p[:lp], z, (l + 1) % 8, r)

	return [z[r]] + permute(p[:lp], z, l, (r + 1) % 8)


def hash0(bytez):
	"""
	From Definition 11 in (2)
	"""
	x, y, z = unpack(bytez)
	zs = [(z[i] % (63 - i)) + i for i in range(4)]
	zs.extend([(z[i + 4] % (64 - i)) + i for i in range(4)])
	zc = check(zs)
	p = PI[x % 35]
	
	if x & 1:
		p = (~p) & 0xff

	zt = permute("{:0>8b}".format(p), zc, 0, 4)
	k = [0] * 8

	for i in range(8):
		ybit = (y >> i) & 1
		pbit = (p >> i) & 1

		if ybit:
			k[i] = ((0x80 | (((~zt[i]) & 0x3f) << 1)|(pbit & 1)) + 1) & 0xff
		else:
			k[i] = (zt[i] << 1) | ((~pbit) & 1)

	return k


def diversify_key(mkey, csn):
	"""
	From CH 2.5 in (2)
	"""	
	cipher = DES.new(mkey)
	crypt_csn = cipher.encrypt(csn)
	div_key = hash0(crypt_csn)

	return div_key


def main():
	parser = argparse.ArgumentParser(description='Script to diversify HID iClass standard keys', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('csn', metavar='CSN', help='HID iClass card serial number (CSN)')
	parser.add_argument('-m', '--masterkey', dest='masterkey_file', help='path to dumped master key file', default='masterkey.hex')
	args = parser.parse_args()

	# Check if dumped master key file exists
	master_key_file_path = os.path.abspath(args.masterkey_file)
	if os.path.isfile(master_key_file_path):
		dumped_master_key = open(master_key_file_path, 'r').readline()
		dumped_master_key = map(ord, dumped_master_key.decode('hex'))
	else:
		print("Unable to find dumped HID iClass master key file at: '{0}'".format(master_key_file_path))
		return

	master_key = reverse_permute_and_shave(dumped_master_key)
	print("Master Key: {0}".format(byte_array_to_string(master_key)))

	diversified_key = diversify_key(byte_array_to_string(master_key).decode('hex'), args.csn.decode('hex'))
	print("Diversified Debit Key (K1): {0}".format(byte_array_to_string(diversified_key)))


if __name__ == "__main__":
	main()