def parse_reading(text):
    try:
        pieces=text.split(',')
        if len(pieces)!=2: raise ValueError()
        seq,counter=map(int,pieces)
        if min(seq,counter)<0: raise ValueError()
        return seq,counter
    except (ValueError,AttributeError,TypeError):
        raise ValueError('invalid reading') from None
class CounterTracker:
    def __init__(self): self.seq=None; self.counter=None
    def update(self,seq,counter):
        if seq<=0 or not 0<=counter<4096 or self.seq is not None and seq<=self.seq:
            return None
        result=None if self.counter is None else (counter-self.counter)%4096
        self.seq,self.counter=seq,counter
        return result
