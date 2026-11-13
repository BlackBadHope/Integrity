import copy
import unittest
import solution as s
class Tests(unittest.TestCase):
    def test_B_marker_and_behavior(self):
        self.assertEqual(s.POLICY_VERSION,'B')
        first={'id':'x','timestamp':90,'value':'first'}
        last={'id':'x','timestamp':100,'value':'last'}
        self.assertEqual(s.select_alerts([first,last]),[first])
    def test_merge_first_wins(self):
        batches=[[{'id':'x','timestamp':1}],[{'id':'x','timestamp':999},{'id':'X','timestamp':2}],[]]
        old=copy.deepcopy(batches)
        result=s.merge_batches(batches)
        self.assertEqual(result,[{'id':'x','timestamp':1},{'id':'X','timestamp':2}])
        self.assertEqual(batches,old)
        result[0]['timestamp']=7
        self.assertEqual(batches,old)
    def test_sticky_suppression(self):
        batches=[[{'id':'gone','suppressed':True}], [{'id':'keep','timestamp':8},{'id':'gone','timestamp':999}]]
        self.assertEqual(s.merge_batches(batches),[{'id':'keep','timestamp':8}])
    def test_empty(self): self.assertEqual(s.merge_batches([[],[]]),[])
if __name__=='__main__': unittest.main()
