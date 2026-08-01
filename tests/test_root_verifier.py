from datetime import UTC,datetime,timedelta
import pytest
from theunderdark.root_verifier import OverseerRootControlVerifier,RootVerificationError

DIGEST="sha256:"+"a"*64
PAYLOAD={"project_id":"project","root_id":"root","policy_revision":"1","root_identity":"sha256:"+"b"*64,"alias":"safe","status":"active","max_bytes":1024}
def response():
    now=datetime.now(UTC); return {"ok":True,"contract_version":"1.0","authorization":{"approval_id":"approval","action":"root.register",**PAYLOAD,"target_digest":DIGEST,"approved_at":now.isoformat(),"expires_at":(now+timedelta(minutes=5)).isoformat(),"redactions_applied":True}}
class Client:
    def __init__(self,value): self.value=value; self.call=None
    def post(self,url,**kwargs): self.call=(url,kwargs); return self.value

def test_control_plane_protocol_and_redacted_request():
    client=Client(response()); verifier=OverseerRootControlVerifier(endpoint="http://127.0.0.1:8766/storage/roots/verify",token_provider=lambda:"token",authorization_ref_provider=lambda a,p,d:"root-auth",http_client=client)
    approval=verifier.verify("root.register",PAYLOAD,DIGEST)
    assert approval.approval_id=="approval" and approval.target_digest==DIGEST
    assert client.call[1]["json"]=={"authorization_ref":"root-auth","action":"root.register",**PAYLOAD,"target_digest":DIGEST}
    assert "Bearer token" not in repr(verifier.__dict__) and "host_path" not in repr(client.call)

@pytest.mark.parametrize("endpoint",["http://localhost:8766/storage/roots/verify","https://127.0.0.1/storage/roots/verify","http://127.0.0.1:8766/other"])
def test_endpoint_must_be_exact_loopback(endpoint):
    with pytest.raises(ValueError): OverseerRootControlVerifier(endpoint=endpoint,token_provider=lambda:"t",authorization_ref_provider=lambda a,p,d:"r",http_client=Client({}))

def test_mismatch_extra_fields_and_server_details_fail_closed():
    value=response(); value["authorization"]["alias"]="other"
    verifier=OverseerRootControlVerifier(endpoint="http://127.0.0.1:8766/storage/roots/verify",token_provider=lambda:"t",authorization_ref_provider=lambda a,p,d:"r",http_client=Client(value))
    with pytest.raises(RootVerificationError) as mismatch: verifier.verify("root.register",PAYLOAD,DIGEST)
    assert mismatch.value.code=="AUTHORIZATION_MISMATCH"
    value=response(); value["authorization"]["host_path"]="/private"
    with pytest.raises(RootVerificationError) as contract: OverseerRootControlVerifier(endpoint="http://127.0.0.1:8766/storage/roots/verify",token_provider=lambda:"t",authorization_ref_provider=lambda a,p,d:"r",http_client=Client(value)).verify("root.register",PAYLOAD,DIGEST)
    assert contract.value.code=="CONTRACT_MISMATCH" and "/private" not in str(contract.value)
