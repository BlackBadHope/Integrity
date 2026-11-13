POLICY_VERSION='B'
def select_alerts(alerts):
    seen=set(); result=[]
    for alert in alerts:
        if alert['id'] not in seen:
            seen.add(alert['id']); result.append(dict(alert))
    return result
def merge_batches(batches):
    seen=set(); result=[]
    for batch in batches:
        for alert in batch:
            if alert['id'] in seen: continue
            seen.add(alert['id'])
            if alert.get('suppressed') is not True: result.append(dict(alert))
    return result
