import unittest
import solution as s
class Tests(unittest.TestCase):
    def test_parser(self):
        self.assertEqual(s.parse_numbers(' 1, -2,+3 '),[1,-2,3])
        self.assertEqual(s.parse_numbers('   '),[])
        for text in ['1,,2','1,','x']:
            with self.assertRaises(ValueError): s.parse_numbers(text)
    def test_chunks(self):
        self.assertEqual(s.chunked(range(5),2),[[0,1],[2,3],[4]])
        self.assertEqual(s.chunked([],3),[])
        self.assertEqual(s.chunked(iter([4,5]),10),[[4,5]])
        self.assertEqual(s.chunked([1,2],1),[[1],[2]])
    def test_size_and_nonmutation(self):
        for size in [0,-1,True,1.5,'2']:
            with self.assertRaises(ValueError): s.chunked([1],size)
        values=[1,2,3]; chunks=s.chunked(values,2); chunks[0].append(9)
        self.assertEqual(values,[1,2,3])
if __name__=='__main__': unittest.main()
