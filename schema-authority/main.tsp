import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace ClipTownTest.PeerAuthority;

@id("RuntimeKind")
enum RuntimeKind {
  web: "web",
  api: "api",
}

@id("ContractEnvelope")
@extension("additionalProperties", false)
model ContractEnvelope {
  @minLength(1)
  repository: string;
  runtime: RuntimeKind;
  generatedWitnessOnly: boolean;
  @minLength(1)
  owner?: string;
}
