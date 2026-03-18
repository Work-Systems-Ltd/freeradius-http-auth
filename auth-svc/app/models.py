from pydantic import BaseModel, Field


class RadiusAuthorizeRequest(BaseModel):
    user_name: str = Field(alias="User-Name", default="")
    user_password: str = Field(alias="User-Password", default="")
    chap_password: str = Field(alias="CHAP-Password", default="")
    chap_challenge: str = Field(alias="CHAP-Challenge", default="")
    nas_ip_address: str = Field(alias="NAS-IP-Address", default="")
    nas_port: str = Field(alias="NAS-Port", default="")

    model_config = {"populate_by_name": True}


class RadiusAuthenticateRequest(BaseModel):
    user_name: str = Field(alias="User-Name", default="")
    user_password: str = Field(alias="User-Password", default="")
    chap_password: str = Field(alias="CHAP-Password", default="")
    chap_challenge: str = Field(alias="CHAP-Challenge", default="")

    model_config = {"populate_by_name": True}
