def validate_ticket(ticket):
    return isinstance(ticket,dict) and isinstance(ticket.get('id'),str) and bool(ticket['id'].strip()) and type(ticket.get('priority')) is int and 1<=ticket['priority']<=5
def audit_ticket(ticket):
    if not validate_ticket(ticket): raise ValueError('invalid ticket')
    email=ticket.get('email'); domain=None
    if isinstance(email,str) and email.count('@')==1:
        local,right=email.split('@')
        if local and right and not any(c.isspace() for c in right): domain=right.lower()
    return {'ticket_id':ticket['id'].strip(),'email_domain':domain,'priority':ticket['priority']}
