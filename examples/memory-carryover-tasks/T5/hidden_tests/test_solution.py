import copy
import unittest
import solution as s
class Tests(unittest.TestCase):
    def test_loader(self):
        self.assertEqual(s.load_config('{"host":"localhost"}'),{'host':'localhost'})
        for text in ['[]','null','7','"x"','{']:
            with self.assertRaises(ValueError): s.load_config(text)
    def test_defaults(self):
        self.assertEqual(s.migrate({}),{'version':2,'endpoint':{'host':'127.0.0.1','port':8123},'timeout_seconds':35.0})
    def test_fields_and_copy(self):
        c={'version':1,'host':'lab.invalid','port':'9001','timeout_ms':1250,'opaque':{'value':['synthetic-placeholder']},'endpoint':{'obsolete':1}}
        old=copy.deepcopy(c); result=s.migrate(c)
        self.assertEqual(result,{'version':2,'endpoint':{'host':'lab.invalid','port':9001},'timeout_seconds':1.25,'opaque':{'value':['synthetic-placeholder']}})
        self.assertEqual(c,old)
        result['opaque']['value'].append('changed')
        self.assertEqual(c,old)
    def test_idempotence_and_v2(self):
        for c in [{},{'port':'12','extra':[1,2]},{'version':2,'endpoint':{'custom':True},'timeout_ms':7}]:
            m=s.migrate(c); self.assertEqual(s.migrate(m),m); self.assertIsNot(s.migrate(m),m)
        with self.assertRaises(ValueError): s.migrate({'version':3})
if __name__=='__main__': unittest.main()
