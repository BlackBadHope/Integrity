"""Native hooks open the turn in their own server session; the model writes in another.

Codex hooks (and Claude Code on Linux) run turn_memory_open through a
hook-owned broker: a separate transport and server session without admission.
The model's session holds the retained admission and performs append/close.
"""
import json

import pytest

from recovery_stand_fixture import Stand
from integrity_guardian import memory_synapse_mcp as mcp


@pytest.fixture
def stand(tmp_path, monkeypatch):
    if __import__('os').name != 'posix':
        pytest.skip('actual POSIX recovery custody requires Linux stand')
    result = Stand(tmp_path, monkeypatch)
    yield result
    result.stop()


def hook_initialize(stand, f):
    """A hook lifecycle broker: no replay reservation, so no recovery binding."""
    caps = {mcp.BROKER_TOOL_SURFACE_CAPABILITY: {
                'protocol': mcp.BROKER_TOOL_SURFACE_PROTOCOL,
                'tools_surface_sha256': mcp._tool_surface_sha256(mcp.tools(profile='turn-curator-v1'))},
            mcp.CONTEXT_ADMISSION_REPLAY_CAPABILITY: {
                'protocol': mcp.CONTEXT_ADMISSION_REPLAY_PROTOCOL,
                'request_identity_field': mcp.CONTEXT_ADMISSION_REPLAY_FIELD,
                'request_identity_format': 'sha256/v1'},
            mcp.CONTEXT_REATTACH_CAPABILITY: {'protocol': mcp.CONTEXT_REATTACH_PROTOCOL},
            'integrity/session-recovery': {'protocol': 'integrity-client/session-recovery/v1'}}
    response = stand.rpc(f, 'initialize', {'protocolVersion': '2024-11-05',
        'clientInfo': {'name': 'integrity-client-turn-broker', 'version': '1.6.0'},
        'capabilities': {'experimental': caps}})
    return response['capabilities'].get('experimental', {})


def model_initialize_without_recovery(stand, f):
    """Variant B: the model broker does not declare same-session recovery."""
    replay, _ = None, None
    import uuid
    from recovery_stand_fixture import digest
    replay = digest('stand-reservation-' + uuid.uuid4().hex)
    caps = {mcp.BROKER_TOOL_SURFACE_CAPABILITY: {
                'protocol': mcp.BROKER_TOOL_SURFACE_PROTOCOL,
                'tools_surface_sha256': mcp._tool_surface_sha256(mcp.tools(profile='turn-curator-v1'))},
            mcp.CONTEXT_ADMISSION_REPLAY_CAPABILITY: {
                'protocol': mcp.CONTEXT_ADMISSION_REPLAY_PROTOCOL,
                'request_identity_field': mcp.CONTEXT_ADMISSION_REPLAY_FIELD,
                'request_identity_format': 'sha256/v1', 'reservation_id': replay},
            mcp.CONTEXT_REATTACH_CAPABILITY: {'protocol': mcp.CONTEXT_REATTACH_PROTOCOL}}
    response = stand.rpc(f, 'initialize', {'protocolVersion': '2024-11-05',
        'clientInfo': {'name': 'integrity-client-turn-broker', 'version': '1.6.0'},
        'capabilities': {'experimental': caps}})
    return replay, response['capabilities'].get('experimental', {})


def own_intent(stand, admission):
    """Native hooks derive the intent from the admitted turn_ref."""
    stand.args['intent_id'] = 'intent:' + admission['prompt_binding']['turn_ref_digest'][7:]
    return stand.args


def raw_tool(stand, f, name, arguments):
    result = stand.rpc(f, 'tools/call', {'name': name, 'arguments': arguments})
    return result, json.loads(result['content'][0]['text'])


def test_hook_session_has_no_recovery_and_opens_without_admission(stand):
    hook = stand.facade()
    caps = hook_initialize(stand, hook)
    assert 'integrity/session-recovery' not in caps
    model = stand.facade()
    replay, model_caps = stand.initialize(model)
    assert 'integrity/session-recovery' in model_caps
    admission = stand.admit(model, 1, replay)
    opened = stand.tool(hook, 'integrity_turn_memory_open', own_intent(stand, admission))
    assert opened['receipt']['identity']['intent_id'] == stand.args['intent_id']


def test_variant_a_model_session_adopts_its_own_registration(stand):
    model = stand.facade()
    replay, _ = stand.initialize(model)
    admission = stand.admit(model, 1, replay)
    hook = stand.facade()
    hook_initialize(stand, hook)
    opened = stand.tool(hook, 'integrity_turn_memory_open', own_intent(stand, admission))
    event = stand.append(model, admission)
    assert event['receipt']['action_outcome'] == 'confirmed-success'
    terminal = stand.close_turn(model, opened, event)
    assert terminal['receipt']['registration_id'] == opened['receipt']['receipt_id']
    assert stand.event_count() == 2


def test_variant_a_foreign_intent_is_not_adopted(stand):
    model = stand.facade()
    replay, _ = stand.initialize(model)
    admission = stand.admit(model, 1, replay)
    hook = stand.facade()
    hook_initialize(stand, hook)
    args = own_intent(stand, admission)
    args['intent_id'] = 'intent:' + 'f' * 64  # another turn_ref
    stand.tool(hook, 'integrity_turn_memory_open', args)
    result, document = raw_tool(stand, model, 'integrity_append_event', {
        'context_admission_id': admission['context_admission_id'],
        'event_uid': 'client:stand46:' + stand.subject_thread + ':foreign',
        'kind': 'thought', 'summary': 'must be denied'})
    assert result.get('isError') is True or document.get('receipt', {}).get('outcome') == 'denied', document
    assert stand.event_count() == 1


def test_variant_a_terminal_registration_is_not_adopted(stand):
    model = stand.facade()
    replay, _ = stand.initialize(model)
    admission = stand.admit(model, 1, replay)
    hook = stand.facade()
    hook_initialize(stand, hook)
    opened = stand.tool(hook, 'integrity_turn_memory_open', own_intent(stand, admission))
    stand.close_turn(hook, opened)  # the hook closed it already (no-event)
    result, document = raw_tool(stand, model, 'integrity_append_event', {
        'context_admission_id': admission['context_admission_id'],
        'event_uid': 'client:stand46:' + stand.subject_thread + ':late',
        'kind': 'thought', 'summary': 'must be denied'})
    assert result.get('isError') is True or document.get('receipt', {}).get('outcome') == 'denied', document
    assert stand.event_count() == 1


def test_variant_b_model_session_without_recovery_writes_ordinarily(stand):
    model = stand.facade()
    replay, caps = model_initialize_without_recovery(stand, model)
    assert 'integrity/session-recovery' not in caps
    admission = stand.admit(model, 1, replay)
    hook = stand.facade()
    hook_initialize(stand, hook)
    opened = stand.tool(hook, 'integrity_turn_memory_open', own_intent(stand, admission))
    event = stand.append(model, admission)
    assert event['receipt']['action_outcome'] == 'confirmed-success'
    terminal = stand.close_turn(model, opened, event)
    assert terminal['receipt']['registration_id'] == opened['receipt']['receipt_id']
    assert stand.event_count() == 2
