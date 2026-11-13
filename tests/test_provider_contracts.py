"""Real TCP/HTTP Greenhouse OAuth and tenant Workday contract tests.

A local HTTP provider server is used deliberately: test observable wire behavior
without a paid account or uploading employee information to a third party.
"""
from __future__ import annotations
import base64
import json
import threading
import unittest
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit
from tahr.provider_clients import GreenhouseV3Reader, WorkdayTenantReader, ProviderError


class ProviderHandler(BaseHTTPRequestHandler):
    calls=[]
    mode="normal"

    def log_message(self,*args):
        return

    def _send(self,code,body,headers=None):
        content=json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(content)))
        for k,v in (headers or {}).items():self.send_header(k,v)
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        self.__class__.calls.append(("POST",self.path,self.headers.get("Authorization")))
        if self.path != "/oauth/token":
            return self._send(404,{"error":"not_found"})
        expected="Basic "+base64.b64encode(b"test-client:local-test-secret").decode()
        if self.headers.get("Authorization")!=expected:
            return self._send(401,{"error":"invalid_client"})
        length=int(self.headers.get("Content-Length","0"))
        body=self.rfile.read(length).decode()
        if "grant_type=client_credentials" not in body:
            return self._send(400,{"error":"invalid_grant"})
        return self._send(200,{"access_token":"local-test-bearer-token","token_type":"Bearer","expires_in":300})

    def do_GET(self):
        self.__class__.calls.append(("GET",self.path,self.headers.get("Authorization")))
        if self.headers.get("Authorization")!="Bearer local-test-bearer-token":
            return self._send(401,{"error":"invalid_token"})
        if self.path.startswith("/v3/jobs"):
            if self.__class__.mode=="rate_limit":
                return self._send(429,{"error":"rate_limit"},{"Retry-After":"1"})
            if "cursor=" not in self.path:
                next_url=(f"http://127.0.0.1:{self.server.server_port}/v3/jobs?cursor=page2"
                          if self.__class__.mode!="evil_redirect" else "https://evil.example/steal")
                return self._send(200,[{"id":101,"name":"Safe synthetic job"}],{"Link":f'<{next_url}>; rel="next"'})
            return self._send(200,[{"id":102,"name":"Other synthetic job"}])
        if self.path=="/tenant/staffing/workers":
            return self._send(200,{"data":[{"id":"worker-1","name":"Never returned"},{"id":"worker-2"}]})
        return self._send(404,{"error":"not_found"})


class TestActualHTTPContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),ProviderHandler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.base=f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        ProviderHandler.calls.clear()
        ProviderHandler.mode="normal"

    def reader(self):
        return GreenhouseV3Reader("test-client","local-test-secret",
            token_url=self.base+"/oauth/token",jobs_url=self.base+"/v3/jobs",allow_local_test_http=True)

    def test_real_oauth_http_and_cursor_pagination(self):
        self.assertEqual(self.reader().list_job_identifiers(),["101","102"])
        calls=ProviderHandler.calls
        self.assertEqual(len(calls),3)
        self.assertEqual(calls[0][0],"POST")
        self.assertEqual(calls[1][2],"Bearer local-test-bearer-token")
        self.assertIn("cursor=page2",calls[2][1])

    def test_real_http_workday_tenant_read_only_redacts_workers(self):
        reader=WorkdayTenantReader(self.base+"/tenant/staffing/workers","local-test-bearer-token",allow_local_test_http=True)
        summary=reader.read_summary()
        self.assertEqual(summary,{"provider":"workday","read_only":True,"item_count":2})
        self.assertNotIn("name",str(summary))
        self.assertEqual(ProviderHandler.calls[-1][0],"GET")

    def test_blocks_cross_host_pagination_and_rate_limits(self):
        ProviderHandler.mode="evil_redirect"
        with self.assertRaisesRegex(ProviderError,"Unexpected pagination destination"):
            self.reader().list_job_identifiers()
        self.assertEqual(len(ProviderHandler.calls),2) # no request to attacker's host
        ProviderHandler.mode="rate_limit"
        with self.assertRaisesRegex(ProviderError,"Rate limited"):
            self.reader().list_job_identifiers()

    def test_no_http_production_or_arbitrary_production_hosts(self):
        with self.assertRaisesRegex(ProviderError,"Production Greenhouse endpoints are fixed"):
            GreenhouseV3Reader("client","secret",token_url=self.base+"/oauth/token")
        with self.assertRaisesRegex(ProviderError,"HTTPS required"):
            WorkdayTenantReader("http://public.example/workers","token-stub-12345")
        with self.assertRaisesRegex(ProviderError,"Invalid upstream endpoint"):
            WorkdayTenantReader("https://user:pass@example.org/worker","token-stub-12345")
        with self.assertRaisesRegex(ProviderError,"approved Workday host"):
            WorkdayTenantReader("https://evil.example/workers", "token-stub-12345")

if __name__=="__main__":
    unittest.main()
