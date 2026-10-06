from http.client import HTTPConnection
from http.server import HTTPServer
from email.message import Message
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from threading import Thread
import unittest
from unittest.mock import patch

import web_app


def analysis_store(events, decisions):
    store = {}
    web_app.store_analysis(store, 'known', events, decisions)
    return store


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.events = json.loads((Path(__file__).parent / 'tests' / 'fixtures' / 'synthetic.json').read_text())['events']

    def test_bundled_example_is_exact_authorized_export(self):
        config = {'port': 0, 'analyses': {}}
        server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
        config['port'] = server.server_port
        thread = Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            connection = HTTPConnection('127.0.0.1', server.server_port)
            connection.request('GET', '/examples/malicious_events.json')
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader('Content-Type'), 'application/json; charset=utf-8')
            self.assertEqual(response.read(), (Path(__file__).parent / 'examples' / 'malicious_events.json').read_bytes())
            connection.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_narrative_only_uses_server_confirmed_seed_and_jev_links(self):
        decisions = [
            {'id': 'seed', 'related': True, 'probability': 1.0},
            {'id': 'child', 'related': True, 'probability': .94},
            {'id': 'later', 'related': False, 'probability': .4},
            {'id': 'unrelated', 'related': False, 'probability': .1},
        ]
        payload = web_app.timeline_input(self.events, decisions)
        self.assertEqual([e['id'] for e in payload], ['seed', 'file-1', 'child'])
        self.assertFalse(any('source_event' in e for e in payload))

    def test_narrative_context_preserves_file_registry_and_remote_thread_fields(self):
        events = self.events + [{'_id':'registry', 'fields': {'@timestamp':['2026-09-21T17:18:51.500Z'],
            'host.name':['WS-01'], 'event.category':['registry'], 'event.action':['RegistryEvent (Value Set)'],
            'process.entity_id':['proc-seed'], 'process.name':['powershell.exe'],
            'registry.path':['HKU\\Example\\UserInitMprLogonScript'],
            'winlog.event_data.TargetImage':['C:\\Windows\\System32\\sihost.exe']}}]
        rows = [{'id':'seed','related':True}, {'id':'child','related':True}]
        payload = web_app.timeline_input(events, rows)
        self.assertEqual([e['id'] for e in payload], ['seed','file-1','registry','child'])
        self.assertEqual(payload[2]['registry']['path'], 'HKU\\Example\\UserInitMprLogonScript')
        self.assertEqual(payload[2]['target']['image'], 'C:\\Windows\\System32\\sihost.exe')

    def test_narrative_input_says_how_each_event_is_linked(self):
        decisions = [{'id': 'seed', 'related': True, 'probability': 1.0, 'reason': 'Confirmed starting execution (user-provided)'},
                     {'id': 'child', 'related': True, 'probability': .94, 'reason': 'lineage (Jev-selected category; not generated prose)'}]
        links = {e['id']: e['link'] for e in web_app.timeline_input(self.events, decisions)}
        self.assertEqual(links, {'seed': {'type': 'confirmed_seed'},
                                 'file-1': {'type': 'same_process_as', 'event_id': 'seed'},
                                 'child': {'type': 'jev_linked', 'probability': .94, 'basis': 'lineage'}})

    def test_narrative_attack_mapping_and_chain_are_validated(self):
        allowed = {'seed', 'child'}
        rows = web_app.validate_timeline({'timeline': [
            {'event_id': 'seed', 'title': 'x', 'summary': 'x', 'evidence_ids': ['seed'], 'tactic': 'execution', 'techniques': ['t1059.003', 'T1059.003', 'bogus', 'T12']},
            {'event_id': 'child', 'title': 'x', 'summary': 'x', 'evidence_ids': ['child'], 'tactic': 'Made-up tactic', 'techniques': 'T1055'}]}, allowed)
        self.assertEqual([(r['tactic'], r['tactic_id'], r['techniques']) for r in rows],
                         [('Execution', 'TA0002', ['T1059.003']), ('', '', [])])
        self.assertEqual(web_app.attack_mapping({'tactic': 'TA0011'})['tactic'], 'Command and Control')
        chain = web_app.clean_chain('- **cmd.exe** [evt:seed] spawned [evt:invented]', allowed)
        self.assertEqual(chain, '- **cmd.exe** [evt:seed] spawned [unknown event]')
        self.assertEqual(web_app.clean_chain(None, allowed), '')
        with self.assertRaises(ValueError):
            web_app.clean_chain('x' * (web_app.MAX_CHAIN + 1), allowed)

    def test_narrative_uses_the_chosen_model_and_returns_the_chain(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self):
                return json.dumps({'model': 'anthropic/claude-sonnet-5.5', 'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps({
                    'timeline': [{'event_id': 'seed', 'title': 'Seed', 'summary': 'Seed ran', 'evidence_ids': ['seed'], 'tactic': 'Execution', 'techniques': ['T1059']}],
                    'execution_chain': '- **cmd.exe** [evt:seed]'})}}]}).encode()
        with patch.object(web_app, 'urlopen', return_value=Response()) as send:
            result = web_app.narrate([{'id': 'seed'}], 'k', 'anthropic/claude-sonnet-5.5')
        self.assertEqual(json.loads(send.call_args.args[0].data)['model'], 'anthropic/claude-sonnet-5.5')
        self.assertIn('ATT&CK summary', json.loads(send.call_args.args[0].data)['messages'][0]['content'])
        self.assertEqual(result['execution_chain'], '- **cmd.exe** [evt:seed]')
        self.assertEqual(result['timeline'][0]['tactic_id'], 'TA0002')
        self.assertEqual(result['model'], 'anthropic/claude-sonnet-5.5')
        for bad in ('', 'no-slash', 'a/b c', 'x' * 121 + '/y', 'https://evil/x'):
            with self.assertRaises(web_app.InputError):
                web_app.narrate([{'id': 'seed'}], 'k', bad)

    def test_narrative_rejects_fabricated_event_and_evidence_ids(self):
        allowed = {'seed', 'child'}
        with self.assertRaises(ValueError):
            web_app.validate_timeline({'timeline': [{'event_id': 'made-up', 'title': 'x', 'summary': 'x', 'evidence_ids': ['seed']}]}, allowed)
        with self.assertRaises(ValueError):
            web_app.validate_timeline({'timeline': [{'event_id': 'child', 'title': 'x', 'summary': 'x', 'evidence_ids': ['made-up']}]}, allowed)

    def test_openrouter_request_uses_selected_events_and_server_side_key(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self):
                return json.dumps({'model': 'deepseek/deepseek-v4.1-flash', 'usage': {'total_tokens': 4},
                                   'choices': [{'message': {'content': json.dumps({'timeline': [
                                       {'event_id': 'seed', 'title': 'Execution', 'summary': 'Observed execution', 'evidence_ids': ['seed']} ]})}}]}).encode()
        with patch.object(web_app, 'urlopen', return_value=Response()) as urlopen:
            result = web_app.narrate([{'id': 'seed', 'time': '2026-01-01T00:00:00Z', 'process': {'name': 'cmd.exe'}}], 'server-secret')
        request = urlopen.call_args.args[0]
        self.assertEqual(request.headers['Authorization'], 'Bearer server-secret')
        self.assertNotIn('server-secret', request.data.decode())
        self.assertEqual(result['timeline'][0]['event_id'], 'seed')

    def test_narrative_retries_when_reasoning_exhausts_completion_budget(self):
        class Response:
            def __init__(self, result): self.result = result
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self): return json.dumps(self.result).encode()
        def fake_urlopen(request, timeout):
            budget = json.loads(request.data)['max_tokens']
            if budget == 8192:
                output = {'choices':[{'finish_reason':'length','message':{'content':None, 'reasoning':'omitted'}}]}
            else:
                output = {'choices':[{'finish_reason':'stop','message':{'content':json.dumps({'timeline':[{'event_id':'seed','title':'Seed','summary':'Confirmed seed','evidence_ids':['seed']}]})}}]}
            return Response(output)
        with patch.object(web_app, 'urlopen', side_effect=fake_urlopen) as provider:
            result = web_app.narrate(web_app.timeline_input(self.events, [{'id':'seed','related':True}]), 'server-key')
        self.assertEqual(provider.call_count, 2)
        self.assertEqual(result['timeline'][0]['event_id'], 'seed')
        self.assertEqual(result['model'], 'deepseek/deepseek-v4.1-flash')

    def test_narrative_recovers_from_truncated_json_without_accepting_partial_output(self):
        class Response:
            def __init__(self, result): self.result = result
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self): return json.dumps(self.result).encode()
        truncated = {'choices': [{'finish_reason': 'length', 'message': {'content': '{"timeline":[{"event_id":"seed"'}}]}
        valid = {'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps({'timeline': [
            {'event_id': 'seed', 'title': 'Execution', 'summary': 'Observed execution', 'evidence_ids': ['seed']}]})}}]}
        with patch.object(web_app, 'urlopen', side_effect=[Response(truncated), Response(valid)]) as send:
            result = web_app.narrate([{'id': 'seed', 'time': '2026-01-01T00:00:00Z'}], 'server-secret')
        self.assertEqual(len(result['timeline']), 1)
        self.assertEqual(send.call_count, 2)
        self.assertGreater(json.loads(send.call_args.args[0].data)['max_tokens'], 1600)

    def test_narrative_http_error_is_not_mislabeled_as_input_400(self):
        from urllib.error import HTTPError
        with tempfile.TemporaryDirectory() as directory:
            config = {'port': 0, 'run_root': Path(directory), 'jev_key': None,
                      'openrouter_key_file': None,
                      'analyses': analysis_store(self.events, [{'id':'seed', 'related':True}])}
            server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
            config['port'] = server.server_port
            thread = Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                headers = {'Content-Type':'application/json', 'Origin':f'http://127.0.0.1:{server.server_port}'}
                connection = HTTPConnection('127.0.0.1', server.server_port)
                with patch.dict(os.environ, {'OPENROUTER_API_KEY': 'server-secret'}), \
                     patch.object(web_app, 'narrate', side_effect=HTTPError('https://openrouter.ai', 429, 'rate limited', Message(), io.BytesIO())):
                    connection.request('POST', '/api/narrate', json.dumps({'analysis_id':'known'}), headers)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 502)
                    self.assertEqual(json.loads(response.read())['error'], 'OpenRouter returned HTTP 429; retry later.')
                connection.close()
            finally:
                server.shutdown(); server.server_close(); thread.join()

    def test_validation_rejects_missing_or_unrecognized_analysis(self):
        with self.assertRaises(ValueError):
            web_app.get_analysis({}, {'analysis_id': 'invented'})
        with self.assertRaises(ValueError):
            web_app.validate_input({'events': self.events, 'seed_id': 'invented', 'description': 'x'})

    def test_analysis_store_evicts_oldest_entry_and_expires_by_age(self):
        store = {}
        for index in range(web_app.MAX_STORED_ANALYSES + 1):
            web_app.store_analysis(store, f'analysis-{index}', self.events, [], now=100 + index)

        self.assertEqual(len(store), web_app.MAX_STORED_ANALYSES)
        self.assertNotIn('analysis-0', store)
        self.assertEqual(list(store), [f'analysis-{index}' for index in range(1, web_app.MAX_STORED_ANALYSES + 1)])
        with self.assertRaisesRegex(web_app.AnalysisUnavailableError, 'fresh Jev analysis'):
            web_app.get_analysis(store, {'analysis_id': 'analysis-0'}, now=105)

        expiring = {}
        web_app.store_analysis(expiring, 'old', self.events, [], now=100)
        with self.assertRaisesRegex(web_app.AnalysisUnavailableError, 'fresh Jev analysis'):
            web_app.get_analysis(expiring, {'analysis_id': 'old'}, now=100 + web_app.ANALYSIS_TTL_SECONDS)
        self.assertEqual(expiring, {})

    def test_narrate_of_expired_analysis_returns_fresh_analysis_message(self):
        config = {'port': 0, 'analyses': {}}
        web_app.store_analysis(config['analyses'], 'expired', self.events, [],
                               now=time.monotonic() - web_app.ANALYSIS_TTL_SECONDS - 1)
        server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
        config['port'] = server.server_port
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            headers = {'Content-Type': 'application/json',
                       'Origin': f'http://127.0.0.1:{server.server_port}'}
            connection = HTTPConnection('127.0.0.1', server.server_port)
            with patch.object(web_app, 'narrate') as provider:
                connection.request('POST', '/api/narrate', json.dumps({'analysis_id': 'expired'}), headers)
                response = connection.getresponse()
                result = json.loads(response.read())
            self.assertEqual(response.status, 400)
            self.assertIn('Complete a fresh Jev analysis', result['error'])
            provider.assert_not_called()
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_provider_status_reads_env_file_on_every_request(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / '.env'
            config = {'jev_key': None, 'openrouter_key_file': None, 'env_file': env}
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(web_app.provider_status(config), {'jev_configured': False, 'openrouter_configured': False,
                                                                   'narrative_model': web_app.MODEL})
                env.write_text('TYPESAFE_API_KEY=ts-secret\n')
                env.chmod(0o600)
                # Added after startup; no restart is needed.
                self.assertTrue(web_app.provider_status(config)['jev_configured'])
                self.assertEqual(web_app.required_key(config, 'jev'), 'ts-secret')
                if os.name != 'nt':
                    env.chmod(0o644)
                    status = web_app.provider_status(config)
                    self.assertFalse(status['jev_configured'])
                    self.assertIn('chmod 600 .env', status['key_problem'])
                    self.assertNotIn('ts-secret', json.dumps(status))
                    self.assertNotIn(directory, json.dumps(status))
                    with self.assertRaises(web_app.ProviderError) as caught:
                        web_app.required_key(config, 'jev')
                    self.assertEqual(caught.exception.status, 503)
                    self.assertIn('chmod 600 .env', str(caught.exception))

    def test_setup_keys_writes_private_env_without_echoing(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / '.env'
            env.write_text('# Copied from .env.example\nTYPESAFE_API_KEY=\nOPENROUTER_API_KEY=\nOTHER=kept\n')
            env.chmod(0o644)
            said = []
            answers = iter(['ts-new', ''])
            web_app.setup_keys(env, ask=lambda prompt: next(answers), say=said.append)
            self.assertEqual(env.read_text(), '# Copied from .env.example\nTYPESAFE_API_KEY=ts-new\nOPENROUTER_API_KEY=\nOTHER=kept\n')
            if os.name != 'nt':
                self.assertEqual(env.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('ts-new', '\n'.join(said))
            # Enter keeps an existing key; a new optional key is added in place.
            answers = iter(['', 'or-new'])
            web_app.setup_keys(env, ask=lambda prompt: next(answers), say=said.append)
            self.assertEqual(env.read_text(), '# Copied from .env.example\nTYPESAFE_API_KEY=ts-new\nOPENROUTER_API_KEY=or-new\nOTHER=kept\n')
            with self.assertRaisesRegex(ValueError, 'malformed'):
                web_app.setup_keys(env, ask=lambda prompt: 'pasted with spaces', say=said.append)
            self.assertIn('TYPESAFE_API_KEY=ts-new', env.read_text())

    def test_openrouter_key_file_is_private_and_assignment_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'openrouter'
            path.write_text('OPENROUTER_API_KEY="test-placeholder"\n')
            path.chmod(0o600)
            self.assertEqual(web_app.load_openrouter_key_file(path), 'test-placeholder')
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'private'):
                web_app.load_openrouter_key_file(path)

    def test_provider_status_never_returns_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'openrouter'
            path.write_text('OPENROUTER_API_KEY="test-placeholder"\n')
            path.chmod(0o600)
            config = {'jev_key': None, 'openrouter_key_file': path}
            with patch.dict('os.environ', {'TYPESAFE_API_KEY': 'local-test-jev'}, clear=True):
                status = web_app.provider_status(config)
            self.assertEqual(status, {'jev_configured': True, 'openrouter_configured': True,
                                      'narrative_model': 'deepseek/deepseek-v4.1-flash'})
            self.assertNotIn('test-placeholder', json.dumps(status))
            path.chmod(0o644)
            self.assertFalse(web_app.provider_status(config)['openrouter_configured'])

    def test_http_local_contract_and_cross_origin_block(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {'port': 0, 'run_root': Path(directory), 'jev_key': None,
                      'analyses': {}, 'input_path': lambda events: Path(__file__)}
            server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
            config['port'] = server.server_port
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection('127.0.0.1', server.server_port)
                payload = json.dumps({'analysis_id': 'invented'})
                headers = {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{server.server_port}'}
                connection.request('POST', '/api/narrate', payload, headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                response.read()
                connection.request('POST', '/api/analyze', payload, dict(headers, Origin='http://evil.invalid'))
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                # The server rejects before consuming the hostile request body.
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_preview_host_and_origin_are_required(self):
        config = {'port': 5000, 'preview_host': 'example.replit.dev',
                  'analyses': {}, 'jev_key': None, 'openrouter_key_file': None}
        server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = HTTPConnection('127.0.0.1', server.server_port)
            connection.request('GET', '/examples/malicious_events.json', headers={'Host': 'evil.invalid'})
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            connection.request('GET', '/', headers={'Host': 'example.replit.dev'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn('https://replit.com', response.getheader('Content-Security-Policy'))
            response.read()
            # The bundled example is published lab data, so preview mode serves it like loopback mode.
            connection.request('GET', '/examples/malicious_events.json', headers={'Host': 'example.replit.dev'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            connection.request('GET', '/api/status', headers={'Host': 'example.replit.dev'})
            response = connection.getresponse()
            self.assertTrue(json.loads(response.read())['example_available'])
            connection.request('GET', '/', headers={'Host': '127.0.0.1:5000'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            connection.request('GET', '/examples/malicious_events.json', headers={'Host': '127.0.0.1:5000'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            headers = {'Host': 'example.replit.dev', 'Content-Type': 'application/json',
                       'Origin': 'https://evil.invalid'}
            connection.request('POST', '/api/narrate', '{}', headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            # The server rejects before consuming the hostile request body, so the reply body may be cut short.
            connection.close()
            connection = HTTPConnection('127.0.0.1', server.server_port)
            headers['Origin'] = 'https://example.replit.dev'
            connection.request('POST', '/api/narrate', '{}', headers)
            response = connection.getresponse()
            # Right host and origin are still not authorization in preview.
            self.assertEqual(response.status, 401)
            response.read()
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_provider_access_decision(self):
        loopback = {'preview_host': None}
        preview = {'preview_host': 'example.replit.dev', 'access_code': 'correct-code'}
        self.assertIsNone(web_app.provider_access(loopback, None))
        self.assertIsNone(web_app.provider_access(preview, 'correct-code'))
        self.assertEqual(web_app.provider_access(preview, None)[0], 401)
        self.assertEqual(web_app.provider_access(preview, '')[0], 401)
        self.assertEqual(web_app.provider_access(preview, 'wrong-code')[0], 403)
        self.assertEqual(web_app.provider_access(preview, 'correct-code ')[0], 403)
        # Preview without a configured code fails closed rather than open.
        self.assertEqual(web_app.provider_access({'preview_host': 'example.replit.dev'}, 'anything')[0], 403)
        self.assertEqual(web_app.provider_access({'preview_host': 'example.replit.dev', 'access_code': ''}, 'x')[0], 403)

    def test_preview_provider_endpoints_require_access_code_before_any_provider_call(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {'port': 5000, 'preview_host': 'example.replit.dev', 'access_code': 'correct-code',
                      'run_root': Path(directory), 'jev_key': None, 'openrouter_key_file': None,
                      'analyses': analysis_store(self.events, [{'id': 'seed', 'related': True}]),
                      'input_path': lambda events: Path(__file__)}
            server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = {'Host': 'example.replit.dev', 'Content-Type': 'application/json', 'Origin': 'https://example.replit.dev'}
            analyze = json.dumps({'events': self.events, 'seed_id': 'seed', 'description': 'Confirmed execution'})
            narrate = json.dumps({'analysis_id': 'known'})

            def request(method, path, body=None, code=None, host=None):
                headers = dict(base, **({web_app.ACCESS_HEADER: code} if code is not None else {}))
                if host:
                    headers['Host'] = host
                    headers['Origin'] = f'http://{host}'
                connection = HTTPConnection('127.0.0.1', server.server_port)
                connection.request(method, path, body, headers)
                response = connection.getresponse()
                result = (response.status, json.loads(response.read()))
                connection.close()
                return result
            try:
                status, body = request('GET', '/api/status')
                self.assertEqual((status, body['access_required']), (200, True))
                with patch.dict(os.environ, {'TYPESAFE_API_KEY': 'owner-key', 'OPENROUTER_API_KEY': 'owner-key'}), \
                     patch.object(web_app.poc, 'recorded_run', return_value=([{'id': 'seed', 'related': True}], {})) as recorded, \
                     patch.object(web_app.poc, 'urlopen') as jev_network, \
                     patch.object(web_app, 'narrate', return_value={'timeline': []}) as drafted, \
                     patch.object(web_app, 'urlopen') as openrouter_network:
                    for path, payload in (('/api/analyze', analyze), ('/api/narrate', narrate), ('/api/access', '{}')):
                        status, body = request('POST', path, payload)
                        self.assertEqual(status, 401, path)
                        self.assertIn('access code required', body['error'])
                        status, body = request('POST', path, payload, code='wrong-code')
                        self.assertEqual(status, 403, path)
                        self.assertIn('access code rejected', body['error'])
                    # Loopback Host in preview mode is not an exemption.
                    status, _ = request('POST', '/api/analyze', analyze, host='127.0.0.1:5000')
                    self.assertEqual(status, 401)
                    self.assertEqual((recorded.call_count, jev_network.call_count, drafted.call_count, openrouter_network.call_count), (0, 0, 0, 0))
                    self.assertEqual(request('POST', '/api/access', '{}', code='correct-code'), (200, {'authorized': True}))
                    self.assertEqual(request('POST', '/api/analyze', analyze, code='correct-code')[0], 200)
                    self.assertEqual(request('POST', '/api/narrate', narrate, code='correct-code')[0], 200)
                    self.assertEqual((recorded.call_count, drafted.call_count), (1, 1))
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_localhost_and_loopback_ip_both_work(self):
        config = {'port': 0, 'analyses': {}, 'jev_key': None, 'openrouter_key_file': None}
        server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
        config['port'] = port = server.server_port
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for host in (f'localhost:{port}', f'127.0.0.1:{port}'):
                connection = HTTPConnection('127.0.0.1', port)
                connection.request('GET', '/', headers={'Host': host})
                response = connection.getresponse()
                self.assertEqual(response.status, 200, host)
                response.read()
                connection.request('POST', '/api/access', '{}', {'Host': host, 'Content-Type': 'application/json', 'Origin': f'http://{host}'})
                response = connection.getresponse()
                self.assertEqual(response.status, 200, host)
                response.read()
                connection.close()
            # A page served from one loopback name cannot post as the other.
            connection = HTTPConnection('127.0.0.1', port)
            connection.request('POST', '/api/access', '{}', {'Host': f'localhost:{port}', 'Content-Type': 'application/json',
                                                             'Origin': f'http://127.0.0.1:{port}'})
            self.assertEqual(connection.getresponse().status, 403)
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_early_replies_are_not_lost_to_a_connection_reset(self):
        """Replies sent before the body is used (access denied, wrong type) must still reach the client."""
        config = {'port': 5000, 'preview_host': 'example.replit.dev', 'access_code': 'correct-code',
                  'analyses': {}, 'jev_key': None, 'openrouter_key_file': None}
        server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        body = json.dumps({'padding': 'x' * (1024 * 1024)})
        headers = {'Host': 'example.replit.dev', 'Origin': 'https://example.replit.dev', 'Content-Type': 'application/json'}
        try:
            for attempt in range(10):
                for extra, expected in (({}, 401), ({web_app.ACCESS_HEADER: 'wrong'}, 403),
                                        ({web_app.ACCESS_HEADER: 'correct-code', 'Content-Type': 'text/plain'}, 415)):
                    connection = HTTPConnection('127.0.0.1', server.server_port, timeout=10)
                    connection.request('POST', '/api/analyze', body, dict(headers, **extra))
                    response = connection.getresponse()
                    self.assertEqual(response.status, expected)
                    self.assertIn('error', json.loads(response.read()))
                    connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_input_errors_explain_what_to_fix(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {'port': 0, 'run_root': Path(directory), 'jev_key': None, 'openrouter_key_file': None, 'analyses': {}}
            server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
            config['port'] = server.server_port
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            headers = {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{server.server_port}'}
            try:
                connection = HTTPConnection('127.0.0.1', server.server_port)
                connection.request('POST', '/api/analyze', json.dumps({'events': self.events, 'seed_id': 'file-1',
                                                                       'description': 'Confirmed'}), headers)
                response = connection.getresponse()
                self.assertEqual((response.status, json.loads(response.read())['error']),
                                 (400, 'Seed must be an execution in the uploaded input'))
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_loopback_mode_needs_no_access_code(self):
        config = {'port': 0, 'analyses': {}, 'jev_key': None, 'openrouter_key_file': None}
        server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
        config['port'] = server.server_port
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = HTTPConnection('127.0.0.1', server.server_port)
            connection.request('GET', '/api/status')
            self.assertFalse(json.loads(connection.getresponse().read())['access_required'])
            connection.request('POST', '/api/access', '{}', {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{server.server_port}'})
            response = connection.getresponse()
            self.assertEqual((response.status, json.loads(response.read())), (200, {'authorized': True}))
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_http_analyze_then_narrate_uses_server_side_results(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {'port': 0, 'run_root': Path(directory), 'jev_key': Path(__file__),
                      'analyses': {}, 'input_path': lambda events: Path(__file__)}
            server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
            config['port'] = server.server_port
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                headers = {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{server.server_port}'}
                connection = HTTPConnection('127.0.0.1', server.server_port)
                rows = [{'id': 'seed', 'related': True, 'probability': 1.0},
                        {'id': 'child', 'related': True, 'probability': 0.94},
                        {'id': 'unrelated', 'related': False, 'probability': 0.1}]
                with patch.object(web_app.poc, 'load_key_file', return_value='hidden'), \
                     patch.dict(os.environ, {'OPENROUTER_API_KEY': 'hidden-openrouter'}), \
                     patch.object(web_app.poc, 'recorded_run', return_value=(rows, {
                         'api_calls': 3, 'reused_answers': 1, 'retried_requests': 2,
                         'evaluated_candidates': 2, 'related_candidates': 1,
                         'elapsed_seconds': 1.5, 'api_elapsed_seconds': 1.2,
                         'input_tokens': 300, 'output_tokens': 40, 'model_requested': 'jev-1.13.0',
                         'threshold': 0.8, 'resumed_from': str(Path(directory) / 'prior-run'),
                         'started_utc': '2026-10-05T12:00:00Z', 'finished_utc': '2026-10-05T12:00:01Z',
                         'request_bytes': 400,
                         'evidence_dir': str(Path(directory) / 'run' / 'evidence'),
                         'telemetry_file': str(Path(directory) / 'private-input.json'),
                         'telemetry_sha256': 'private-hash', 'seed_id': 'seed',
                     })) as recorded, \
                     patch.object(web_app, 'narrate', return_value={'timeline': [], 'model': web_app.MODEL}) as drafted:
                    connection.request('POST', '/api/analyze', json.dumps({
                        'events': self.events, 'seed_id': 'seed', 'description': 'Confirmed execution'}), headers)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    result = json.loads(response.read())
                    self.assertNotIn('hidden', json.dumps(result))
                    self.assertNotIn(directory, json.dumps(result))
                    self.assertEqual(set(result['summary']), {
                        'api_calls', 'reused_answers', 'retried_requests', 'evaluated_candidates',
                        'related_candidates', 'elapsed_seconds', 'api_elapsed_seconds',
                        'input_tokens', 'output_tokens', 'model', 'threshold', 'resumed'})
                    self.assertEqual(result['summary']['model'], 'jev-1.13.0')
                    self.assertEqual(result['summary']['threshold'], 0.8)
                    self.assertTrue(result['summary']['resumed'])
                    self.assertEqual(recorded.call_args.args[1], 'seed')
                    connection.request('POST', '/api/narrate', json.dumps({
                        'analysis_id': result['analysis_id'], 'decisions': [{'id': 'unrelated', 'related': True}]}), headers)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                    self.assertEqual([e['id'] for e in drafted.call_args.args[0]], ['seed', 'file-1', 'child'])
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_provider_failures_are_named_and_not_reported_as_input_errors(self):
        from urllib.error import HTTPError, URLError
        with tempfile.TemporaryDirectory() as directory:
            config = {'port': 0, 'run_root': Path(directory), 'jev_key': None, 'openrouter_key_file': None,
                      'analyses': analysis_store(self.events, [{'id': 'seed', 'related': True}]),
                      'input_path': lambda events: Path(__file__)}
            server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
            config['port'] = server.server_port
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            headers = {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{server.server_port}'}
            analyze = json.dumps({'events': self.events, 'seed_id': 'seed', 'description': 'Confirmed execution'})
            narrate = json.dumps({'analysis_id': 'known'})

            def post(path, body):
                connection = HTTPConnection('127.0.0.1', server.server_port)
                connection.request('POST', path, body, headers)
                response = connection.getresponse()
                result = (response.status, json.loads(response.read())['error'])
                connection.close()
                return result
            try:
                with patch.dict(os.environ, {}, clear=True):
                    self.assertEqual(post('/api/analyze', analyze), (503, 'TypeSafe API key missing; add TYPESAFE_API_KEY to .env (or run python3 web_app.py --setup-keys) and retry.'))
                    self.assertEqual(post('/api/narrate', narrate), (503, 'OpenRouter API key missing; add OPENROUTER_API_KEY to .env (or run python3 web_app.py --setup-keys) and retry.'))
                with patch.dict(os.environ, {'TYPESAFE_API_KEY': 'bad', 'OPENROUTER_API_KEY': 'bad'}):
                    with patch.object(web_app.poc, 'recorded_run', side_effect=HTTPError(web_app.poc.API, 401, 'unauthorized', Message(), io.BytesIO())):
                        self.assertEqual(post('/api/analyze', analyze), (502, 'TypeSafe rejected the API key (HTTP 401); check TYPESAFE_API_KEY.'))
                    # Exhausted Jev retries still fail the analysis with a provider-named message.
                    with patch.object(web_app.poc, 'urlopen', side_effect=HTTPError(web_app.poc.API, 520, 'origin error', Message(), io.BytesIO())) as send, \
                            patch.object(web_app.poc, 'sleep') as pause:
                        self.assertEqual(post('/api/analyze', analyze), (502, 'TypeSafe returned HTTP 520 after 3 attempts; retry later.'))
                        self.assertEqual((send.call_count, pause.call_count), (3, 2))
                    with patch.object(web_app.poc, 'urlopen', side_effect=HTTPError(web_app.poc.API, 401, 'unauthorized', Message(), io.BytesIO())) as send, \
                            patch.object(web_app.poc, 'sleep') as pause:
                        self.assertEqual(post('/api/analyze', analyze), (502, 'TypeSafe rejected the API key (HTTP 401); check TYPESAFE_API_KEY.'))
                        self.assertEqual((send.call_count, pause.call_count), (1, 0))
                    with patch.object(web_app.poc, 'recorded_run', side_effect=URLError('offline')):
                        self.assertEqual(post('/api/analyze', analyze), (502, 'TypeSafe could not be reached or timed out; retry later.'))
                    with patch.object(web_app.poc, 'recorded_run', side_effect=ValueError('Invalid Jev answer')):
                        self.assertEqual(post('/api/analyze', analyze), (502, 'TypeSafe returned an unusable Jev answer; no decision was assumed.'))
                    with patch.object(web_app, 'narrate', side_effect=HTTPError(web_app.OPENROUTER, 401, 'unauthorized', Message(), io.BytesIO())):
                        self.assertEqual(post('/api/narrate', narrate), (502, 'OpenRouter rejected the API key (HTTP 401); check OPENROUTER_API_KEY.'))
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    class JevAnswer:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"answers":{"related":{"type":"noul","noul":0.91},"evidence":{"type":"choice","choice":"lineage"}}}'

    @staticmethod
    def outage():
        from urllib.error import HTTPError
        return HTTPError(web_app.poc.API, 520, 'origin error', Message(), io.BytesIO())

    def start_server(self, run_root, **extra):
        """A fresh server process state (as after a restart) sharing only the on-disk run root."""
        config = {'port': 0, 'run_root': Path(run_root), 'jev_key': None, 'openrouter_key_file': None,
                  'analyses': {}, 'input_path': lambda events: Path(__file__), **extra}
        server = HTTPServer(('127.0.0.1', 0), web_app.handler_class(config))
        config['port'] = server.server_port
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown(); server.server_close(); thread.join()
        self.addCleanup(stop)
        headers = {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{server.server_port}'}

        def post(value):
            connection = HTTPConnection('127.0.0.1', server.server_port)
            connection.request('POST', '/api/analyze', json.dumps(value), headers)
            response = connection.getresponse()
            result = (response.status, json.loads(response.read()))
            connection.close()
            return result
        return config, post

    def test_failed_analysis_can_be_resumed_without_repaying_answered_calls(self):
        Response, outage = self.JevAnswer, self.outage
        with tempfile.TemporaryDirectory() as directory:
            config, post = self.start_server(directory)
            body = {'events': self.events, 'seed_id': 'seed', 'description': 'Confirmed execution'}
            with patch.dict(os.environ, {'TYPESAFE_API_KEY': 'hidden-jev'}), patch.object(web_app.poc, 'sleep'):
                # One answered call, then an outage that outlasts the retries.
                with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]):
                    status, failed = post(body)
                self.assertEqual(status, 502)
                self.assertEqual(failed['error'], 'TypeSafe returned HTTP 520 after 3 attempts; retry later.')
                self.assertEqual((failed['resume_available'], failed['reusable_answers']), (True, 1))
                self.assertNotIn('hidden-jev', json.dumps(failed))
                self.assertNotIn(directory, json.dumps(failed))
                with patch.object(web_app.poc, 'urlopen') as never:
                    # Changed inputs have no saved resume point and are refused before any provider call.
                    self.assertEqual(post(dict(body, description='Other', resume=True))[0], 409)
                    self.assertEqual(post(dict(body, events=self.events[:-1], resume=True))[0], 409)
                    # A plain Analyze for the same inputs offers the saved progress instead of paying again.
                    status, saved = post(body)
                    self.assertEqual(status, 409)
                    self.assertEqual((saved['resume_available'], saved['reusable_answers']), (True, 1))
                    self.assertIn('Resume to reuse them', saved['error'])
                    never.assert_not_called()
                with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), Response()]) as send:
                    status, result = post(dict(body, resume=True))
                self.assertEqual(status, 200)
                self.assertEqual(send.call_count, 2)
                self.assertEqual((result['summary']['api_calls'], result['summary']['reused_answers']), (2, 1))
                self.assertNotIn(directory, json.dumps(result))
                self.assertEqual(result['summary']['resumed'], True)
                disk_summary_path = next(Path(directory).glob('*/summary.json'))
                disk_summary = json.loads(disk_summary_path.read_text())
                self.assertIn(directory, json.dumps(disk_summary))
                self.assertTrue(Path(disk_summary['resumed_from']).is_dir())
                self.assertTrue(all(row['related'] for row in result['decisions']))
                # Exactly the one answer saved by the failed run is marked reused, with its answer time and no private path.
                reused = [row for row in result['decisions'] if 'reused' in row]
                self.assertEqual(len(reused), 1)
                self.assertEqual(list(reused[0]['reused']), ['answered_utc'])
                self.assertRegex(reused[0]['reused']['answered_utc'], r'^\d{4}-\d\d-\d\dT.*Z$')
                self.assertNotIn(directory, json.dumps(result['decisions']))
                self.assertIn(result['analysis_id'], config['analyses'])
                # A finished run does not block a fresh Analyze; a failure before any attempts log offers no resume.
                with patch.object(web_app.poc, 'recorded_run', side_effect=outage()):
                    status, failed = post(body)
                self.assertEqual(status, 502)
                self.assertNotIn('resume_available', failed)
                # Analyze with fresh=true deliberately starts over even when saved progress exists.
                with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]):
                    self.assertEqual(post(body)[0], 502)
                with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), Response(), Response()]) as send:
                    status, result = post(dict(body, fresh=True))
                self.assertEqual((status, send.call_count, result['summary']['reused_answers']), (200, 3, 0))
                self.assertTrue(all('reused' not in row for row in result['decisions']))

    def test_resume_point_survives_a_server_restart(self):
        Response, outage = self.JevAnswer, self.outage
        body = {'events': self.events, 'seed_id': 'seed', 'description': 'Confirmed execution'}
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'TYPESAFE_API_KEY': 'hidden-jev'}), patch.object(web_app.poc, 'sleep'):
            _, post = self.start_server(directory)
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]):
                status, failed = post(body)
            self.assertEqual((status, failed['reusable_answers']), (502, 1))
            # Other inputs fail later and must not be picked up by the restarted server.
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), Response(), outage(), outage(), outage()]):
                self.assertEqual(post(dict(body, description='Other'))[0], 502)
            # Restart: nothing in memory carries over, only the private run root on disk.
            _, post = self.start_server(directory)
            with patch.object(web_app.poc, 'urlopen') as never:
                status, saved = post(body)
                self.assertEqual((status, saved['reusable_answers']), (409, 1))
                never.assert_not_called()
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), Response()]) as send:
                status, result = post(dict(body, resume=True))
            self.assertEqual((status, send.call_count), (200, 2))
            self.assertEqual((result['summary']['api_calls'], result['summary']['reused_answers']), (2, 1))
            # The run log of the other inputs was never used.
            runs = [json.loads(p.read_text()) for p in Path(directory).glob('*/run.json')]
            self.assertEqual(len(runs), 3)
            self.assertEqual(sum(r['resumed_from'] is not None for r in runs), 1)

    def test_lost_resume_response_can_be_recovered_without_repeating_calls(self):
        Response, outage = self.JevAnswer, self.outage
        body = {'events': self.events, 'seed_id': 'seed', 'description': 'Confirmed execution'}
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'TYPESAFE_API_KEY': 'hidden-jev'}), patch.object(web_app.poc, 'sleep'):
            _, post = self.start_server(directory)
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]):
                self.assertEqual(post(body)[0], 502)
            # The server accepts a resume, answers one more call, then fails; the browser never sees
            # the reply. Resuming again continues from that successor run, not the original one.
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]) as send:
                status, lost = post(dict(body, resume=True))
            self.assertEqual((status, lost['reusable_answers'], send.call_count), (502, 2, 4))
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response()]) as send:
                status, result = post(dict(body, resume=True))
            self.assertEqual((status, send.call_count), (200, 1))
            self.assertEqual((result['summary']['api_calls'], result['summary']['reused_answers']), (1, 2))
            # The successful resume reply is lost too: resuming again reuses every answer, with no provider call.
            with patch.object(web_app.poc, 'urlopen') as never:
                status, again = post(dict(body, resume=True))
                never.assert_not_called()
            self.assertEqual(status, 200)
            self.assertEqual((again['summary']['api_calls'], again['summary']['reused_answers']), (0, 3))
            # Same verdicts; now every Jev decision is marked reused, keeping each original answer time.
            strip = lambda rows: [{k: v for k, v in row.items() if k != 'reused'} for row in rows]
            self.assertEqual(strip(again['decisions']), strip(result['decisions']))
            self.assertEqual(sum('reused' in row for row in result['decisions']), 2)
            self.assertEqual(sum('reused' in row for row in again['decisions']), 3)
            earlier = {row['id']: row['reused'] for row in result['decisions'] if 'reused' in row}
            self.assertEqual({row['id']: row['reused'] for row in again['decisions'] if row['id'] in earlier}, earlier)
            self.assertNotIn('reused', again['decisions'][0], 'the analyst-confirmed seed is never marked reused')
            self.assertNotEqual(again['analysis_id'], result['analysis_id'])

    @staticmethod
    def age(path, days):
        """Backdate a run directory (all of its files) or an input copy by whole days."""
        when = time.time() - days * 86400
        paths = [path] + ([Path(folder) / name for folder, dirs, files in os.walk(path) for name in dirs + files] if path.is_dir() else [])
        for item in paths:
            os.utime(item, (when, when))

    @staticmethod
    def run_infos(root):
        return {p.parent.name: json.loads(p.read_text()) for p in Path(root).glob('*/run.json')}

    def test_retention_removes_expired_runs_and_copies_but_keeps_newest_resume_point(self):
        Response, outage = self.JevAnswer, self.outage
        body = {'events': self.events, 'seed_id': 'seed', 'description': 'Confirmed execution'}
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'TYPESAFE_API_KEY': 'hidden-jev'}), patch.object(web_app.poc, 'sleep'):
            root = Path(directory)
            preserve = lambda events: web_app.preserve_input(root, events)
            _, post = self.start_server(root, input_path=preserve)
            # Run A saves one answer; its resume, run B, saves a second one and fails too; run C has other inputs.
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]):
                self.assertEqual(post(body)[0], 502)
            first = self.run_infos(root)
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]):
                self.assertEqual(post(dict(body, resume=True))[1]['reusable_answers'], 2)
            second = self.run_infos(root)
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]):
                self.assertEqual(post(dict(body, description='Other'))[0], 502)
            infos = self.run_infos(root)
            (a,), (b,) = first, set(second) - set(first)
            (c,) = set(infos) - set(second)
            self.assertTrue(all((root / info['input_copy']).is_file() for info in infos.values()))
            # Everything is 20 days old except run B's last writes; B's input copy is old too (written at its start).
            for name in (a, c):
                self.age(root / name, 20)
            for info in infos.values():
                self.age(root / info['input_copy'], 20)
            orphan_old, orphan_new = web_app.preserve_input(root, []), web_app.preserve_input(root, [])
            self.age(orphan_old, 20)
            (root / 'notes.txt').write_text('not a web run')
            (root / 'manual-run').mkdir()
            self.age(root / 'notes.txt', 400); self.age(root / 'manual-run', 400)

            self.assertEqual(web_app.cleanup_runs(root, 14 * 86400), (5, 0))
            remaining = {p.name for p in root.iterdir()}
            self.assertEqual(remaining, {b, infos[b]['input_copy'], orphan_new.name, 'notes.txt', 'manual-run'})

            # The kept newest run still resumes with every answer, through a server that applies retention itself.
            _, post = self.start_server(root, input_path=preserve, retention_seconds=14 * 86400)
            with patch.object(web_app.poc, 'urlopen') as never:
                self.assertEqual(post(dict(body, description='Other', resume=True))[0], 409)
                never.assert_not_called()
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response()]) as send:
                status, result = post(dict(body, resume=True))
            self.assertEqual((status, send.call_count), (200, 1))
            self.assertEqual((result['summary']['api_calls'], result['summary']['reused_answers']), (1, 2))
            # Once every run has expired, Analyze finds no saved progress and starts over instead of offering 409.
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]):
                self.assertEqual(post(body)[0], 502)
            for path in root.iterdir():
                self.age(path, 15)
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), Response(), Response()]) as send:
                status, result = post(body)
            self.assertEqual((status, send.call_count, result['summary']['reused_answers']), (200, 3, 0))
            self.assertEqual(len(self.run_infos(root)), 1)

    def test_retention_never_deletes_an_analysis_in_progress(self):
        Response, outage = self.JevAnswer, self.outage
        body = {'events': self.events, 'seed_id': 'seed', 'description': 'Confirmed execution'}
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'TYPESAFE_API_KEY': 'hidden-jev'}), patch.object(web_app.poc, 'sleep'):
            root = Path(directory)
            config, post = self.start_server(root, input_path=lambda events: web_app.preserve_input(root, events), active=set())
            with patch.object(web_app.poc, 'urlopen', side_effect=[Response(), outage(), outage(), outage()]):
                self.assertEqual(post(body)[0], 502)
            stray = web_app.preserve_input(root, [])
            sweeps = []

            def answer_after_cleanup(*args, **kwargs):
                # A zero-day cleanup in the middle of the resume: everything is expired, yet only the
                # unrelated stray copy may go; the resume source, new run and both input copies stay.
                sweeps.append(web_app.cleanup_runs(root, 0, config['active']))
                return Response()
            with patch.object(web_app.poc, 'urlopen', side_effect=answer_after_cleanup):
                status, result = post(dict(body, resume=True))
            self.assertEqual(status, 200)
            self.assertEqual(sweeps[0], (1, 0))
            self.assertEqual(set(sweeps[1:]), {(0, 0)})
            self.assertFalse(stray.exists())
            infos = self.run_infos(root)
            self.assertEqual(len(infos), 2)
            self.assertTrue(all((root / info['input_copy']).is_file() for info in infos.values()))
            private_summary = json.loads(next(root.glob('*/summary.json')).read_text())
            self.assertRegex(private_summary['telemetry_sha256'], r'^[0-9a-f]{64}$')
            self.assertIn(directory, json.dumps(private_summary))
            self.assertNotIn(directory, json.dumps(result))
            # Nothing stays marked in use once the analysis ends, so the same sweep now clears everything.
            self.assertEqual(config['active'], set())
            self.assertEqual(web_app.cleanup_runs(root, 0, config['active']), (4, 0))
            self.assertEqual(list(root.iterdir()), [])

    def test_script_launch_reports_named_provider_errors(self):
        """Exercise `python3 web_app.py`, not just the imported module; no network is used."""
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        with tempfile.TemporaryDirectory() as directory:
            env = {k: v for k, v in os.environ.items() if k not in ('TYPESAFE_API_KEY', 'OPENROUTER_API_KEY')}
            missing = Path(directory) / 'missing'
            # Startup applies the retention period: an input copy last written 15 days ago is removed.
            runs = Path(directory) / 'runs'
            runs.mkdir(mode=0o700)
            expired = web_app.preserve_input(runs, [])
            self.age(expired, 15)
            command = [sys.executable, str(Path(__file__).parent / 'web_app.py'), '--port', str(port),
                       '--key-file', str(missing), '--openrouter-key-file', str(missing), '--env-file', str(missing), '--run-root', str(Path(directory) / 'runs')]
            headers = {'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{port}'}
            body = json.dumps({'events': self.events, 'seed_id': 'seed', 'description': 'Confirmed execution'})

            def analyze(extra_env):
                process = subprocess.Popen(command, env=dict(env, **extra_env), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                try:
                    for _ in range(100):
                        try:
                            connection = HTTPConnection('127.0.0.1', port, timeout=10)
                            connection.request('POST', '/api/analyze', body, headers)
                            break
                        except ConnectionRefusedError:
                            time.sleep(0.05)
                    response = connection.getresponse()
                    result = (response.status, json.loads(response.read())['error'])
                    connection.close()
                    return result
                finally:
                    process.terminate()
                    process.wait(timeout=10)
                    process.stdout.close()

            self.assertEqual(analyze({}), (503, 'TypeSafe API key missing; add TYPESAFE_API_KEY to .env (or run python3 web_app.py --setup-keys) and retry.'))
            self.assertFalse(expired.exists())
            # An unreachable proxy makes the provider call fail locally, proving the launch path reaches call_provider.
            unreachable = {'TYPESAFE_API_KEY': 'fake', 'https_proxy': 'http://127.0.0.1:9', 'HTTPS_PROXY': 'http://127.0.0.1:9', 'no_proxy': '', 'NO_PROXY': ''}
            self.assertEqual(analyze(unreachable), (502, 'TypeSafe could not be reached or timed out; retry later.'))


if __name__ == '__main__':
    unittest.main()
