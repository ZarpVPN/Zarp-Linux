from pathlib import Path
import importlib.util,unittest
from cryptography.exceptions import InvalidTag

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('quic_fake',ROOT/'tools/compact-quic-fake.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class CompactQUICFakeTests(unittest.TestCase):
    def test_authenticated_clienthello_is_preserved(self):
        original=(ROOT/'vendor/runtime/blobs/quic_vk.bin').read_bytes()
        compact=(ROOT/'resources/quic_vk_1200.bin').read_bytes()
        _,before,*_=module.decode(original)
        _,after,*_=module.decode(compact)
        self.assertEqual(compact,module.compact(original))
        self.assertEqual(len(compact),1200)
        self.assertEqual(after[:len(before)],before)
        self.assertEqual(after[len(before):],bytes(len(after)-len(before)))
        typ,pos=module.var(after,0);offset,pos=module.var(after,pos);size,pos=module.var(after,pos)
        self.assertEqual((typ,offset,size),(6,0,512))
        self.assertEqual(after[pos],1) # Complete TLS ClientHello, not a truncated fake.
        self.assertEqual(int.from_bytes(after[pos+1:pos+4],'big')+4,size)

    def test_corrupt_ciphertext_is_rejected(self):
        compact=bytearray((ROOT/'resources/quic_vk_1200.bin').read_bytes());compact[-1]^=1
        with self.assertRaises(InvalidTag):module.decode(compact)

if __name__=='__main__':unittest.main()
