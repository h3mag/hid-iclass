import sys
from Crypto.Cipher import DES

'''
Papers used:
(1) Heart of Darkness - exploring the uncharted backwaters of HID iCLASS security
(2) Dismantling iClass and iClass Elite
'''

'''
from Definition 10 in (2)
'''
PI = [0x0F,0x17,0x1B,0x1D,0x1E,0x27,0x2B,0x2D,0x2E,0x33,0x35,0x39,0x36,0x3A,0x3C,0x47,0x4B,0x4D,0x4E,0x53,0x55,0x56,0x59,0x5A,0x5C,0x63,0x65,0x66,0x69,0x6A,0x6C,0x71,0x72,0x74,0x78]

def ba2s(ba):
	'''
	helper method to convert a bytearay into a hexstring
	'''
	return ''.join(map(chr, ba)).encode("hex")

def reverse_permute(key):
	n = 3
	while n > 0:
		tkey = [0]*8
		n -= 1
		for i in range(8):
			p = 0
			mask = 0x80>>i
			for x in range(8):
				p >>= 1
				if key[x] & mask:
					p |= 0x80
			tkey[i] = p
		key = tkey
	return key

def shave(key):
	return map(lambda k: k&0xfe, key)

'''
from Appendix C-B in (1)
'''
def reverse_permute_and_shave(key):
	key = reverse_permute(key)
	return shave(key)

def unpack(bytez):
	'''
	helper method to unpack a bytearray into x,y,z
	x,y are 8bits each
	z is an array of dim 8 with 6 bits per member 
	'''
	v = int(bytez.encode("hex"), 16)
	x = 0
	y = 0
	z = [0]*8
	for i in range(8):
		z[i] = v&0x3f
		v >>= 6
	y = v&0xff
	v >>= 8
	x = v&0xff
	return x,y,z

def ck(i,j,z):
	if (i == 1) and (j == -1):
		return z

	if (j == -1):
		return ck(i-1, i-2, z)
	
	if z[i] == z[j]:
		z[i] = j
		return ck(i, j-1, z)
	else:
		return ck(i, j-1, z)
'''
from Definition 8 in (2)
'''
def check(zs):
	zc1 = ck(3,2,zs[0:4])
	zc2 = ck(3,2,zs[4:8])
	zc = zc1+zc2
	return zc

'''
from Definition 9 in (2)
'''
def permute(p,z,l,r):
	rlp = len(p)
	if rlp==0:
		return []
	lp = rlp-1
	if p[lp]=="1":
		return [(z[l]+1)&0x3f]+permute(p[:lp], z, (l+1)%8, r)
	else:
		return [z[r]]+permute(p[:lp], z, l, (r+1)%8)

'''
from Definition 11 in (2)
'''
def hash0(bytez):
	x,y,z = unpack(bytez)
	zs = [(z[i]%(63-i))+i for i in range(4)]
	zs.extend([(z[i+4]%(64-i))+i for i in range(4)])
	zc = check(zs)
	p = PI[x%35]
	if x&1:
		p = (~p)&0xff
	zt = permute("{:0>8b}".format(p), zc, 0, 4)
	k = [0]*8
	for i in range(8):
		ybit = (y>>i)&1
		pbit = (p>>i)&1
		if ybit:
			k[i]=((0x80|(((~zt[i])&0x3f)<<1)|(pbit&1))+1)&0xff
		else:
			k[i]=(zt[i]<<1)|((~pbit)&1)
	return k

'''
from ch 2.5 in (2)
'''
def diversify_key(mkey, csn):
	cipher = DES.new(mkey)
	crypt_csn = cipher.encrypt(csn)
	div_key = hash0(crypt_csn)
	return div_key

def print_usage():
	print "%s <CSN>" % (sys.argv[0])

def main(hcsn):
	with open("masterkey.hex", "r") as f:
		DUMPED_MASTER_KEY = f.readline()

	MASTER_KEY = reverse_permute_and_shave( map(ord, DUMPED_MASTER_KEY.decode("hex") ) )
	print "MASTER KEY:", ba2s(MASTER_KEY)

	div_key = diversify_key(ba2s(MASTER_KEY).decode("hex"), hcsn.decode("hex"))
	print "DIVERSIFIED DEBIT KEY (K1):", ba2s(div_key)

if __name__ == "__main__":
	if len(sys.argv) == 2:
		main(sys.arv[1])
	else:
		print_usage()
