import copy
import json
import unittest
import solution as s
class Tests(unittest.TestCase):
    def test_validation(self):
        self.assertTrue(s.validate_ticket({'id':' T ','priority':3}))
        for t in [None,{}, {'id':' ','priority':2},{'id':'x','priority':True},{'id':'x','priority':0},{'id':2,'priority':1}]:
            self.assertFalse(s.validate_ticket(t))
            with self.assertRaises(ValueError): s.audit_ticket(t)
    def test_exact_projection(self):
        t={'id':' T-7 ','priority':2,'email':'Alice@Example.COM','body':'opaque private text','ip':'192.0.2.19','extra':{'sensitive':'value'}}
        old=copy.deepcopy(t)
        result=s.audit_ticket(t)
        self.assertEqual(result,{'ticket_id':'T-7','email_domain':'example.com','priority':2})
        self.assertEqual(t,old)
        for forbidden in ['Alice','opaque private text','192.0.2.19','sensitive']: self.assertNotIn(forbidden,json.dumps(result))
    def test_email_boundaries(self):
        for email in [None,3,'invalid','@host','x@','x@y@z','x@bad host','x@bad\thost']:
            self.assertIsNone(s.audit_ticket({'id':'x','priority':1,'email':email})['email_domain'])
if __name__=='__main__': unittest.main()
