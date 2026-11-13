import copy
import unittest
import solution as s
class Tests(unittest.TestCase):
    def test_normalization(self):
        source={'id':' 7 ','name':' x ','enabled':1,'extra':'untouched'}
        old=copy.deepcopy(source)
        self.assertEqual(s.normalize_record(source),{'id':'7','name':'x','enabled':True})
        self.assertEqual(source,old)
        with self.assertRaises(ValueError): s.normalize_record({'id':'  '})
    def test_export_contract(self):
        self.assertEqual(s.export_records([]),'id;name;enabled\n')
        rows=[{'id':2,'name':' A;B ','enabled':True},{'id':'3','name':'Тест'}]
        self.assertEqual(s.export_records(rows),'id;name;enabled\n2;"A;B";yes\n3;Тест;no\n')
    def test_quoting_and_nonmutation(self):
        rows=[{'id':'x','name':'line\nbreak "q"','enabled':False}]
        old=copy.deepcopy(rows)
        self.assertEqual(s.export_records(rows),'id;name;enabled\nx;"line\nbreak ""q""";no\n')
        self.assertEqual(rows,old)
if __name__=='__main__': unittest.main()
