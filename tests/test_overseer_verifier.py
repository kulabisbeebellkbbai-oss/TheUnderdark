from datetime import UTC,datetime,timedelta

import pytest

from theunderdark.overseer_verifier import OverseerAuthorizationVerifier,OverseerVerificationError


DIGEST="sha256:"+"a"*64
def request(): return {"authorization_ref":"auth","project_id":"project","root_id":"root","policy_revision":"1"}
def response():
    now=datetime.now(UTC)
    return {"ok":True,"contract_version":"1.0","authorization":{"authorization_ref":"auth","request_id":"req","project_id":"project","root_id":"root","action":"file.write","target_digest":DIGEST,"policy_revision":"1","claim_id":"claim","approval_id":"approval","approved_at":now.isoformat(),"expires_at":(now+timedelta(minutes=5)).isoformat(),"limits":{"max_bytes":8},"redactions_applied":True}}

class Client:
    def __init__(self,value): self.value=value; self.call=None
    def post(self,url,**kwargs): self.call=(url,kwargs); return self.value

def test_exact_loopback_request_and_strict_snapshot():
    client=Client(response()); verifier=OverseerAuthorizationVerifier(endpoint="http://127.0.0.1:8766/storage/authorizations/verify",token_provider=lambda:"secret-token",http_client=client)
    snapshot=verifier.verify("file.write",request(),DIGEST)
    assert snapshot.target_digest==DIGEST and snapshot.limits=={"max_bytes":8}
    assert client.call[1]["json"]=={"authorization_ref":"auth","request_digest":DIGEST,"project_id":"project","root_id":"root","action":"file.write","policy_revision":"1"}
    assert client.call[1]["headers"]["authorization"]=="Bearer secret-token" and "secret-token" not in repr(verifier.__dict__)

@pytest.mark.parametrize("endpoint",["http://localhost:8766/storage/authorizations/verify","http://0.0.0.0:8766/storage/authorizations/verify","https://127.0.0.1/storage/authorizations/verify","http://127.0.0.1:8766/other","http://user:pass@127.0.0.1:8766/storage/authorizations/verify"])
def test_non_exact_endpoint_is_rejected(endpoint):
    with pytest.raises(ValueError): OverseerAuthorizationVerifier(endpoint=endpoint,token_provider=lambda:"x",http_client=Client({}))

def test_mismatch_and_extra_response_fields_fail_closed():
    value=response(); value["authorization"]["target_digest"]="sha256:"+"b"*64
    verifier=OverseerAuthorizationVerifier(endpoint="http://127.0.0.1:8766/storage/authorizations/verify",token_provider=lambda:"token",http_client=Client(value))
    with pytest.raises(OverseerVerificationError) as mismatch: verifier.verify("file.write",request(),DIGEST)
    assert mismatch.value.code=="AUTHORIZATION_MISMATCH"
    value=response(); value["authorization"]["raw_approval"]={}
    with pytest.raises(OverseerVerificationError) as contract: OverseerAuthorizationVerifier(endpoint="http://127.0.0.1:8766/storage/authorizations/verify",token_provider=lambda:"token",http_client=Client(value)).verify("file.write",request(),DIGEST)
    assert contract.value.code=="CONTRACT_MISMATCH"

def test_server_error_is_redacted_and_token_provider_failure_is_closed():
    verifier=OverseerAuthorizationVerifier(endpoint="http://127.0.0.1:8766/storage/authorizations/verify",token_provider=lambda:"token",http_client=Client({"ok":False,"error":{"code":"CLAIM_INVALID","message":"private claim details"}}))
    with pytest.raises(OverseerVerificationError) as error: verifier.verify("file.write",request(),DIGEST)
    assert error.value.code=="CLAIM_INVALID" and "private" not in str(error.value)
    def unavailable(): raise RuntimeError("private token-store failure")
    verifier=OverseerAuthorizationVerifier(endpoint="http://127.0.0.1:8766/storage/authorizations/verify",token_provider=unavailable,http_client=Client({}))
    with pytest.raises(OverseerVerificationError) as unavailable_error: verifier.verify("file.write",request(),DIGEST)
    assert unavailable_error.value.code=="DEPENDENCY_UNAVAILABLE" and "private" not in str(unavailable_error.value)
