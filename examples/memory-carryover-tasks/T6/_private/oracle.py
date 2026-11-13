def parse_numbers(text):
    if not text.strip(): return []
    return [int(part.strip()) for part in text.split(',')]
def chunked(values,size):
    if type(size) is not int or size<=0: raise ValueError('invalid size')
    result=[]; block=[]
    for value in values:
        block.append(value)
        if len(block)==size: result.append(block); block=[]
    if block: result.append(block)
    return result
