"""Narrow client for Overseer's authoritative storage-verification route."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Callable, Mapping, Protocol
from urllib.parse import urlsplit

from .journal import AuthorizationSnapshot


class VerificationTransport(Protocol):
    def post(self, url: str, *, headers: Mapping[str, str], json: Mapping[str, object], timeout: float) -> Mapping[str, object]: ...


class OverseerVerificationError(RuntimeError):
    def __init__(self, code: str, message: str): super().__init__(message); self.code=code


class OverseerAuthorizationVerifier:
    ROUTE = "/storage/authorizations/verify"
    SNAPSHOT_FIELDS = frozenset({"authorization_ref","request_id","project_id","root_id","action","target_digest","policy_revision","claim_id","approval_id","approved_at","expires_at","limits","redactions_applied"})

    def __init__(self, *, endpoint: str, token_provider: Callable[[], str], http_client: VerificationTransport, timeout: float = 5.0) -> None:
        parsed=urlsplit(endpoint)
        if parsed.scheme!="http" or parsed.hostname!="127.0.0.1" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path.rstrip("/")!=self.ROUTE:
            raise ValueError("Overseer verifier endpoint must be the exact loopback HTTP authorization route")
        if not callable(token_provider) or http_client is None: raise TypeError("token provider and HTTP client are required")
        if not 0 < timeout <= 30: raise ValueError("verification timeout must be finite and bounded")
        self.endpoint=endpoint; self._token_provider=token_provider; self._http_client=http_client; self._timeout=timeout

    def verify(self, action: str, request: Mapping[str, object], request_digest: str) -> AuthorizationSnapshot:
        required=("authorization_ref","project_id","root_id","policy_revision")
        if not isinstance(action,str) or not action or any(not isinstance(request.get(k),str) or not request.get(k) for k in required) or not _digest(request_digest):
            raise OverseerVerificationError("INVALID_ARGUMENT","authoritative verification input is invalid")
        try: token=self._token_provider()
        except Exception as error: raise OverseerVerificationError("DEPENDENCY_UNAVAILABLE","Overseer authentication is unavailable") from error
        if not isinstance(token,str) or not token or "\n" in token or "\r" in token:
            raise OverseerVerificationError("DEPENDENCY_UNAVAILABLE","Overseer authentication is unavailable")
        payload={"authorization_ref":request["authorization_ref"],"request_digest":request_digest,"project_id":request["project_id"],"root_id":request["root_id"],"action":action,"policy_revision":request["policy_revision"]}
        try:
            response=self._http_client.post(self.endpoint,headers={"authorization":f"Bearer {token}","content-type":"application/json"},json=payload,timeout=self._timeout)
        except Exception as error:
            raise OverseerVerificationError("DEPENDENCY_UNAVAILABLE","Authoritative verification is unavailable") from error
        finally:
            token=""  # retain no credential value beyond the call
        if not isinstance(response,Mapping): raise OverseerVerificationError("DEPENDENCY_UNAVAILABLE","Authoritative verification returned an invalid response")
        if response.get("ok") is not True:
            error=response.get("error") if isinstance(response.get("error"),Mapping) else {}
            code=str(error.get("code") or "AUTHORIZATION_INVALID")
            if code not in {"INVALID_ARGUMENT","AUTHORIZATION_REQUIRED","AUTHORIZATION_MISMATCH","AUTHORIZATION_INVALID","CLAIM_INVALID"}: code="AUTHORIZATION_INVALID"
            raise OverseerVerificationError(code,"Authoritative storage verification failed")
        if set(response)!={"ok","contract_version","authorization"} or response.get("contract_version")!="1.0" or not isinstance(response.get("authorization"),Mapping):
            raise OverseerVerificationError("CONTRACT_MISMATCH","Authoritative verification response contract is invalid")
        snapshot=response["authorization"]
        if set(snapshot)!=self.SNAPSHOT_FIELDS or snapshot.get("redactions_applied") is not True:
            raise OverseerVerificationError("CONTRACT_MISMATCH","Authorization snapshot fields are invalid")
        strings=("authorization_ref","request_id","project_id","root_id","action","target_digest","policy_revision","claim_id","approval_id","approved_at","expires_at")
        if any(not isinstance(snapshot.get(name),str) or not snapshot[name] for name in strings): raise OverseerVerificationError("CONTRACT_MISMATCH","Authorization snapshot values are invalid")
        limits=snapshot.get("limits")
        if not isinstance(limits,Mapping) or any(not isinstance(k,str) or not isinstance(v,int) or isinstance(v,bool) or v<0 for k,v in limits.items()): raise OverseerVerificationError("CONTRACT_MISMATCH","Authorization limits are invalid")
        try: approved=_timestamp(str(snapshot["approved_at"])); expires=_timestamp(str(snapshot["expires_at"]))
        except ValueError as error: raise OverseerVerificationError("CONTRACT_MISMATCH","Authorization timestamps are invalid") from error
        if expires<=approved or snapshot["authorization_ref"]!=request["authorization_ref"] or snapshot["project_id"]!=request["project_id"] or snapshot["root_id"]!=request["root_id"] or snapshot["action"]!=action or snapshot["policy_revision"]!=request["policy_revision"] or snapshot["target_digest"]!=request_digest:
            raise OverseerVerificationError("AUTHORIZATION_MISMATCH","Authorization snapshot does not match the canonical request")
        return AuthorizationSnapshot(str(snapshot["authorization_ref"]),str(snapshot["request_id"]),str(snapshot["project_id"]),str(snapshot["root_id"]),str(snapshot["action"]),str(snapshot["target_digest"]),str(snapshot["policy_revision"]),str(snapshot["claim_id"]),str(snapshot["approval_id"]),str(snapshot["approved_at"]),str(snapshot["expires_at"]),dict(limits))


def _timestamp(value:str)->datetime:
    parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    if parsed.tzinfo is None: raise ValueError("timezone required")
    return parsed.astimezone(UTC)
def _digest(value:str)->bool: return isinstance(value,str) and value.startswith("sha256:") and len(value)==71 and all(c in "0123456789abcdef" for c in value[7:])

__all__=["OverseerAuthorizationVerifier","OverseerVerificationError","VerificationTransport"]
