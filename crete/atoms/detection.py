from typing import Literal, TypeAlias

from pydantic import BaseModel, Field

Language: TypeAlias = Literal["c", "cpp", "c++", "jvm"]


class AIxCCChallengeFullMode(BaseModel):
    type: Literal["full"] = "full"
    base_ref: str


class AIxCCChallengeDeltaMode(BaseModel):
    type: Literal["delta"] = "delta"
    base_ref: str
    delta_ref: str


class AIxCCChallengeSarifMode(BaseModel):
    type: Literal["sarif"] = "sarif"
    base_ref: str


AIxCCChallengeMode: TypeAlias = (
    AIxCCChallengeFullMode | AIxCCChallengeDeltaMode | AIxCCChallengeSarifMode
)


class BlobInfo(BaseModel):
    harness_name: str
    sanitizer_name: str
    blob: bytes


class SarifReport(BaseModel):
    model_config = {"extra": "allow"}

    version: str = Field(default="2.1.0")
    runs: list[dict[str, object]] = Field(default_factory=list)


class Detection(BaseModel):
    mode: AIxCCChallengeMode | None
    vulnerability_identifier: str
    project_name: str
    language: Language
    blobs: list[BlobInfo] = []
    sarif_report: SarifReport | None = None
