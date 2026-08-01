"""Strict loopback client for Overseer root-control authorization."""
from __future__ import annotations

from datetime import UTC,datetime
from typing import Callable,Mapping
from urllib.parse import urlsplit

from .overseer_verifier import VerificationTransport
from .root_registry import ControlPlaneApproval


class RootVerificationError(RuntimeError):
    def __init__(self,code:str,message:str): super().__init__(message); self.code=code


class OverseerRootControlVerifier:
    ROUTE="/storage/roots/verify"
    RESPONSE_FIELDS=frozenset({"approval_id","action","project_id","root_id","policy_revision","root_identity","alias","status","max_bytes","target_digest","approved_at","expires_at","redactions_applied"})
    PAYLOAD_FIELDS=frozenset({"project_id","root_id","policy_revision","root_identity","alias","status","max_bytes"})

    def __init__(self,*,endpoint:str,token_provider:Callable[[],str],authorization_ref_provider:Callable[[str,Mapping[str,object],str],str],http_client:VerificationTransport,timeout:float=5.0)->None:
        parsed=urlsplit(endpoint)
        if parsed.scheme!="http" or parsed.hostname!="127.0.0.1" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path.rstrip("/")!=self.ROUTE: raise ValueError("root verifier endpoint must be the exact loopback HTTP route")
        if not callable(token_provider) or not callable(authorization_ref_provider) or http_client is None: raise TypeError("token, authorization reference, and transport providers are required")
        if not 0<timeout<=30: raise ValueError("verification timeout must be finite and bounded")
        self.endpoint=endpoint; self._token_provider=token_provider; self._authorization_ref_provider=authorization_ref_provider; self._http_client=http_client; self._timeout=timeout

    def verify(self,action:str,payload:Mapping[str,object],target_digest:str)->ControlPlaneApproval:
        if action not in {"root.register","root.transition"} or set(payload)!=self.PAYLOAD_FIELDS or not _digest(target_digest): raise RootVerificationError("INVALID_ARGUMENT","root verification input is invalid")
        if any(name!="max_bytes" and (not isinstance(payload[name],str) or not payload[name]) for name in self.PAYLOAD_FIELDS) or not isinstance(payload["max_bytes"],int) or isinstance(payload["max_bytes"],bool) or payload["max_bytes"]<1: raise RootVerificationError("INVALID_ARGUMENT","root verification values are invalid")
        try: token=self._token_provider(); authorization_ref=self._authorization_ref_provider(action,payload,target_digest)
        except Exception as error: raise RootVerificationError("DEPENDENCY_UNAVAILABLE","root authorization dependencies are unavailable") from error
        if not isinstance(token,str) or not token or "\n" in token or "\r" in token or not isinstance(authorization_ref,str) or not authorization_ref or "\n" in authorization_ref or "\r" in authorization_ref: raise RootVerificationError("DEPENDENCY_UNAVAILABLE","root authorization dependencies are unavailable")
        request={"authorization_ref":authorization_ref,"action":action,**dict(payload),"target_digest":target_digest}
        try: response=self._http_client.post(self.endpoint,headers={"authorization":f"Bearer {token}","content-type":"application/json"},json=request,timeout=self._timeout)
        except Exception as error: raise RootVerificationError("DEPENDENCY_UNAVAILABLE","authoritative root verification is unavailable") from error
        finally: token=""; authorization_ref=""
        if not isinstance(response,Mapping): raise RootVerificationError("CONTRACT_MISMATCH","root verification response is invalid")
        if response.get("ok") is not True:
            error=response.get("error") if isinstance(response.get("error"),Mapping) else {}; code=str(error.get("code") or "AUTHORIZATION_INVALID")
            if code not in {"INVALID_ARGUMENT","AUTHORIZATION_REQUIRED","AUTHORIZATION_MISMATCH","AUTHORIZATION_INVALID"}: code="AUTHORIZATION_INVALID"
            raise RootVerificationError(code,"authoritative root verification failed")
        if set(response)!={"ok","contract_version","authorization"} or response.get("contract_version")!="1.0" or not isinstance(response.get("authorization"),Mapping): raise RootVerificationError("CONTRACT_MISMATCH","root verification contract is invalid")
        record=response["authorization"]
        if set(record)!=self.RESPONSE_FIELDS or record.get("redactions_applied") is not True: raise RootVerificationError("CONTRACT_MISMATCH","root authorization fields are invalid")
        expected=(action,payload["project_id"],payload["root_id"],payload["policy_revision"],payload["root_identity"],payload["alias"],payload["status"],payload["max_bytes"],target_digest)
        actual=tuple(record.get(name) for name in ("action","project_id","root_id","policy_revision","root_identity","alias","status","max_bytes","target_digest"))
        try: approved=_timestamp(record["approved_at"]); expires=_timestamp(record["expires_at"])
        except (TypeError,ValueError) as error: raise RootVerificationError("CONTRACT_MISMATCH","root authorization timestamps are invalid") from error
        if actual!=expected or expires<=approved or not isinstance(record.get("approval_id"),str) or not record["approval_id"]: raise RootVerificationError("AUTHORIZATION_MISMATCH","root authorization does not match the requested revision")
        return ControlPlaneApproval(str(record["approval_id"]),action,str(payload["project_id"]),str(payload["root_id"]),str(payload["policy_revision"]),target_digest,"approved",str(record["expires_at"]))


def _digest(value): return isinstance(value,str) and value.startswith("sha256:") and len(value)==71 and all(c in "0123456789abcdef" for c in value[7:])
def _timestamp(value):
    parsed=datetime.fromisoformat(str(value).replace("Z","+00:00"))
    if parsed.tzinfo is None: raise ValueError
    return parsed.astimezone(UTC)

__all__=["OverseerRootControlVerifier","RootVerificationError"]
