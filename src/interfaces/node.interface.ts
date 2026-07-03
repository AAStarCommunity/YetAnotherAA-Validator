export interface NodeKeyPair {
  nodeId: string;
  nodeName: string;
  privateKey: string;
  publicKey: string;
  description: string;
}

export interface NodeState {
  nodeId: string;
  nodeName: string;
  /**
   * Raw BLS private key (0x-hex). On disk it is EITHER this plaintext field (dev/legacy)
   * OR an encrypted `keystore` (#5, EIP-2335 — prod). When a keystore is present it is
   * decrypted at load using NODE_KEY_PASSPHRASE and this field is populated in memory.
   */
  privateKey: string;
  /** EIP-2335 encrypted keystore (#5). When set, `privateKey` is derived from it at load. */
  keystore?: import("../utils/keystore.util.js").Eip2335Keystore;
  publicKey: string;
  stakeStatus?: "not_staked" | "staked" | "unstaking";
  stakeAmount?: string;
  stakedAt?: string;
  registeredAt?: string;
  createdAt: string;
  description: string;
}

export interface SignerConfig {
  description: string;
  contractAddress: string;
  registeredAt: string;
  totalNodes: number;
  owner: string;
  keyPairs: NodeKeyPair[];
  contractInfo: {
    name: string;
    address: string;
    network: string;
    owner: string;
    registeredNodes: number;
  };
}
