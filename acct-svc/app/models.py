from pydantic import BaseModel, Field


class PostAuthRequest(BaseModel):
    user_name: str = Field(alias="User-Name", default="")
    reply_message: str = Field(alias="Reply-Message", default="")
    packet_type: str = Field(alias="Packet-Type", default="")
    nas_ip_address: str = Field(alias="NAS-IP-Address", default="")

    model_config = {"populate_by_name": True}


class AccountingRequest(BaseModel):
    user_name: str = Field(alias="User-Name", default="")
    acct_status_type: str = Field(alias="Acct-Status-Type", default="")
    acct_session_id: str = Field(alias="Acct-Session-Id", default="")
    acct_session_time: int = Field(alias="Acct-Session-Time", default=0)
    acct_input_octets: int = Field(alias="Acct-Input-Octets", default=0)
    acct_output_octets: int = Field(alias="Acct-Output-Octets", default=0)
    nas_ip_address: str = Field(alias="NAS-IP-Address", default="")
    framed_ip_address: str = Field(alias="Framed-IP-Address", default="")

    model_config = {"populate_by_name": True}
