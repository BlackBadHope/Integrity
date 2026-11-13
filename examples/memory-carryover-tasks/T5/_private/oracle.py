import copy
import json
def load_config(text):
    result=json.loads(text)
    if not isinstance(result,dict): raise ValueError('expected object')
    return result
def migrate(config):
    result=copy.deepcopy(config)
    version=result.get('version',1)
    if version==2: return result
    if version!=1: raise ValueError('unknown version')
    result['endpoint']={'host':result.pop('host','127.0.0.1'),'port':int(result.pop('port',8123))}
    result['timeout_seconds']=result.pop('timeout_ms',35000)/1000
    result['version']=2
    return result
