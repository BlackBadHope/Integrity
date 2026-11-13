import unittest
import solution as s
class Tests(unittest.TestCase):
    def test_parser(self):
        self.assertEqual(s.parse_reading(' 2 , 105 '),(2,105))
        for text in ['1','1,2,3','a,2','-1,4','1,-2']:
            with self.assertRaises(ValueError): s.parse_reading(text)
    def test_stale_prime(self):
        t=s.CounterTracker()
        self.assertIsNone(t.update(0,3900))
        self.assertIsNone(t.update(1,100))
        self.assertEqual(t.update(2,105),5)
    def test_wrap(self):
        t=s.CounterTracker()
        self.assertIsNone(t.update(1,4090))
        self.assertEqual(t.update(4,3),9)
        self.assertEqual(t.update(5,9),6)
    def test_ignored_samples_preserve_baseline(self):
        t=s.CounterTracker(); t.update(2,100)
        for seq,counter in [(2,200),(1,300),(0,400),(3,4096),(4,-1)]:
            self.assertIsNone(t.update(seq,counter))
        self.assertEqual(t.update(5,107),7)
if __name__=='__main__': unittest.main()
