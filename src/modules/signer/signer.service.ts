import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NodeKeyPair } from "../../interfaces/node.interface.js";
import { BlsSigner } from "./bls-signer.interface.js";
import { LocalKeySigner } from "./local-key.signer.js";

/**
 * Pluggable factory for the BLS key-custody backend (#50, arch #67 port-adapter example).
 * Default `local` reproduces the existing in-process key behaviour exactly. A BLS-capable
 * KMS/HSM adapter (future) slots in here behind SIGNER_BACKEND — the signing output stays
 * conformance-identical because the algorithm/wire is the fixed kernel, not part of this seam.
 */
@Injectable()
export class SignerService {
  private readonly logger = new Logger(SignerService.name);

  constructor(private readonly config: ConfigService) {}

  forNode(node: NodeKeyPair): BlsSigner {
    const backend = this.config.get<string>("signerBackend") || "local";
    switch (backend) {
      case "local":
        return new LocalKeySigner(node.privateKey);
      // case "kms": return new KmsSigner(...);  // future (#50): needs a BLS-capable KMS/HSM
      // case "hsm": return new HsmSigner(...);
      default:
        throw new Error(`unknown SIGNER_BACKEND="${backend}" (supported: local)`);
    }
  }
}
