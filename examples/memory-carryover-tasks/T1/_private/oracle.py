import csv
import io
def normalize_record(record):
    result = dict(id=str(record['id']).strip(), name=str(record.get('name','')).strip(), enabled=bool(record.get('enabled',False)))
    if not result['id']:
        raise ValueError('empty id')
    return result
def export_records(records):
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter=';', lineterminator='\n')
    writer.writerow(['id','name','enabled'])
    for record in records:
        r = normalize_record(record)
        writer.writerow([r['id'],r['name'],'yes' if r['enabled'] else 'no'])
    return output.getvalue()
