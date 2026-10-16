"""Small independent synthetic controls for dangerous format interpretation errors."""
import struct
import unittest
import zlib
from firmware_structure import parse

def image():
    b=bytearray(0x410)
    b[:4]=b'UPD\0';b[0x2a0:0x2a4]=b'UPD\0'
    b[12:18]=b'MC8223'
    for at,value in ((4,0x200),(8,0x200),(0x34,3),(0x38,0x200),(0x3c,len(b)-0x200),(0x2e8,2)):
        struct.pack_into('<I',b,at,value)
    # Two same-name entries. +0x14 deliberately resembles an invalid file offset.
    for i in range(2):
        at=0x2ec+92*i
        b[at:at+3]=b'dup'
        struct.pack_into('<IIII',b,at+12,0x200+8*i,8,0xf0000000+i,3)
    b[0x400:]=bytes(range(16))
    fix_crc(b)
    return b

def fix_crc(b):
    struct.pack_into('<I',b,0x40,zlib.crc32(b[0x200:])&0xffffffff)

class StructureTests(unittest.TestCase):
    def test_uses_relative_offset_not_destination(self):
        p=parse(image())
        self.assertEqual([r['absolute_offset'] for r in p['rows']],[0x400,0x408])
        self.assertEqual([r['occurrence'] for r in p['rows']],[0,1])
    def test_complete_payload_hash_changes(self):
        b=image();p=parse(b);b[-1]^=1;fix_crc(b)
        self.assertNotEqual(p['rows'][1]['raw_sha256'],parse(b)['rows'][1]['raw_sha256'])
    def test_crc_corruption_rejected(self):
        b=image();b[-1]^=1
        with self.assertRaises(AssertionError):parse(b)
    def test_wrong_declared_length_rejected(self):
        b=image();struct.pack_into('<I',b,0x3c,123)
        with self.assertRaises(AssertionError):parse(b)
    def test_overlapping_payload_rejected(self):
        b=image();struct.pack_into('<I',b,0x2ec+92+12,0x200);fix_crc(b)
        with self.assertRaises(AssertionError):parse(b)
    def test_missing_inner_magic_rejected(self):
        b=image();b[0x2a0]=0;fix_crc(b)
        with self.assertRaises(AssertionError):parse(b)
    def test_unassigned_tail_rejected_for_this_profile(self):
        b=image();b+=b'extra';struct.pack_into('<I',b,0x3c,len(b)-0x200);fix_crc(b)
        with self.assertRaises(AssertionError):parse(b)

if __name__=='__main__':
    unittest.main(verbosity=2)
