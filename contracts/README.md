# AAStarValidator Smart Contracts

Solidity smart contracts for BLS signature verification and ERC-4337 account
abstraction. These contracts work in conjunction with the BLS signer service to
provide secure, aggregated signature verification on-chain.

## Overview

This package contains the complete smart contract implementation for:

- **AAStarValidator**: BLS signature verification contract
- **AAStarAccount**: ERC-4337 compliant smart contract accounts (v0.6, v0.7,
  v0.8)
- **AAStarAccountFactory**: Account creation factories for multiple EntryPoint
  versions
- **Deployment Scripts**: Foundry scripts for contract deployment

## Architecture

### Core Contracts

#### AAStarValidator.sol

The validator contract manages BLS public key registration and signature
verification:

- **Node Registration**: Register BLS public keys for signer nodes
- **Signature Verification**: Verify aggregated BLS signatures on-chain
- **EIP-2537 Integration**: Uses Ethereum's BLS12-381 precompiles for efficient
  verification

Key functions:

- `registerPublicKey(bytes32 nodeId, bytes calldata publicKey)` - Register a
  signer node
- `isRegistered(bytes32 nodeId)` - Check if a node is registered
- `verifyAggregateSignature(...)` - Verify aggregated BLS signatures

#### AAStarAccount (v0.6/v0.7/v0.8)

ERC-4337 compliant smart contract wallets with:

- **Multi-version Support**: Compatible with EntryPoint v0.6, v0.7, and v0.8
- **Flexible Validation**: Support for both AAStarValidator and standard ECDSA
- **Modular Design**: Clean separation between account logic and validation

> The account + factory contracts were retired (#163 Phase 1) — see the note
> below. Account deployment now lives in `airaccount-contract`.

## Project Structure

> **Note (#163 Phase 1):** the ERC-4337 account + factory contracts
> (`AAStarAccountBase`, `AAStarAccountV6/7/8`, `AAStarAccountFactoryV6/7/8`) and
> their `DeployAAStar*` bundle scripts were **retired**. This repo now ships the
> DVT **validator only**; the production account line is `airaccount-contract`'s
> `AAStarAirAccountV7` (EntryPoint v0.7, behind its ValidatorRouter).
> `AAStarValidator` is router-mountable via `IAAStarAlgorithm.validate()` (algId
> 0x01).

```
contracts/
├── src/
│   └── AAStarValidator.sol              # DVT BLS validator + IAAStarAlgorithm.validate() (algId 0x01)
├── script/
│   └── DeployStakeBoundValidator.s.sol # deploy + wire to SuperPaymaster Registry (Plan A v3)
├── test/                                # Contract tests
├── lib/                                 # Dependencies (Foundry)
├── foundry.toml                         # Foundry configuration
└── remappings.txt                       # Import remappings

```

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) - Ethereum
  development toolchain
- Node.js >= 18.0.0 (for scripts)

## Installation

```bash
cd contracts

# Install Foundry dependencies
forge install

# Build contracts
forge build
```

## Testing

```bash
# Run all tests
forge test

# Run tests with gas reporting
forge test --gas-report

# Run specific test
forge test --match-test testFunctionName

# Run tests with verbosity
forge test -vvv
```

## Deployment

### Environment Setup

Create a `.env` file in the contracts directory:

```bash
# Network RPC
ETH_RPC_URL=https://sepolia.infura.io/v3/YOUR_INFURA_KEY

# Deployer private key (use with caution)
ETH_PRIVATE_KEY=your_private_key_here

# Existing validator address (for account/factory deployment)
EXISTING_VALIDATOR=0xYourValidatorAddress
```

### Deploy Validator Contract

The validator contract must be deployed first:

```bash
# Deploy to Sepolia (v0.6)
forge script script/DeployAAStar.s.sol:DeployAAStar \
  --rpc-url $ETH_RPC_URL \
  --private-key $ETH_PRIVATE_KEY \
  --broadcast \
  --legacy

# Deploy to Sepolia (v0.7)
forge script script/DeployAAStarV7.s.sol:DeployAAStarV7 \
  --rpc-url $ETH_RPC_URL \
  --private-key $ETH_PRIVATE_KEY \
  --broadcast \
  --legacy

# Deploy to Sepolia (v0.8)
forge script script/DeployAAStarV8.s.sol:DeployAAStarV8 \
  --rpc-url $ETH_RPC_URL \
  --private-key $ETH_PRIVATE_KEY \
  --broadcast \
  --legacy
```

### Deploy Account Factory

After deploying the validator, deploy the account factory:

```bash
# Set the validator address
export EXISTING_VALIDATOR=0xYourDeployedValidatorAddress

# Deploy factory (v0.7 example)
EXISTING_VALIDATOR=$EXISTING_VALIDATOR forge script script/DeployAAStarV7.s.sol:DeployAAStarV7 \
  --rpc-url $ETH_RPC_URL \
  --private-key $ETH_PRIVATE_KEY \
  --broadcast \
  --legacy
```

### Deployment Verification

After deployment, verify your contracts on Etherscan:

```bash
forge verify-contract \
  --chain-id 11155111 \
  --constructor-args $(cast abi-encode "constructor(address)" $ENTRY_POINT) \
  $DEPLOYED_ADDRESS \
  src/AAStarValidator.sol:AAStarValidator \
  --etherscan-api-key $ETHERSCAN_API_KEY
```

## EntryPoint Versions

### v0.6 (0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)

- Standard ERC-4337 v0.6 implementation
- Uses `initCode` for account creation
- Compatible with most bundlers

### v0.7 (0x0000000071727De22E5E9d8BAf0edAc6f37da032)

- Updated UserOperation structure
- Separate `factory` and `factoryData` fields
- Enhanced paymaster support

### v0.8 (0x0576a174D229E3cFA37253523E645A78A0C91B57)

- Latest ERC-4337 specification
- Improved gas efficiency
- Enhanced security features

## BLS Signature Verification

### On-chain Verification Flow

1. **Node Registration**: Signer nodes register their BLS public keys
2. **Signature Aggregation**: Off-chain signature aggregation by signer service
3. **On-chain Verification**: AAStarValidator verifies the aggregated signature

### Signature Format

BLS signatures use the BLS12-381 curve with EIP-2537 precompiles:

- **Public Key**: 96 bytes (compressed G1 point)
- **Signature**: 192 bytes (compressed G2 point)
- **Message Point**: 192 bytes (G2 point derived from message hash)

### Gas Costs

Signature verification gas depends on the number of signers:

- Base cost: ~300k gas
- Per-signer: ~50k gas
- 3 signers: ~450k gas
- 5 signers: ~550k gas

## Integration with Signer Service

The validator contracts work with the BLS signer service:

1. **Deploy Validator**: Deploy AAStarValidator contract
2. **Configure Signer**: Set `VALIDATOR_CONTRACT_ADDRESS` in signer service
3. **Register Nodes**: Use signer service API to register nodes on-chain
4. **Sign Messages**: Signer service generates BLS signatures
5. **Verify On-chain**: Validator contract verifies aggregated signatures

## Security Considerations

### Validator Contract

- **Owner-only Registration**: Only contract owner can register nodes
- **Public Key Validation**: Validates BLS public key format
- **Immutable Registration**: Registered keys cannot be modified (only added)

### Account Contracts

- **Signature Validation**: All operations require valid signatures
- **Nonce Management**: Prevents replay attacks
- **Access Control**: Only owner can execute transactions

### Deployment Best Practices

1. **Private Key Security**: Never commit private keys to git
2. **Testnet First**: Deploy to testnets (Sepolia) before mainnet
3. **Verification**: Always verify contracts on Etherscan
4. **Audit**: Consider professional audits for production deployment
5. **Multi-sig Owner**: Use multi-sig for validator contract ownership

## Development

### Compile Contracts

```bash
forge build
```

### Run Tests

```bash
forge test
```

### Format Code

```bash
forge fmt
```

### Generate Gas Report

```bash
forge test --gas-report
```

### Local Development

Start a local Anvil node:

```bash
anvil
```

Deploy to local node:

```bash
forge script script/DeployAAStarV7.s.sol:DeployAAStarV7 \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
```

## Supported Networks

- **Ethereum Sepolia**: Testnet (recommended for development)
- **Ethereum Mainnet**: Production
- **Polygon**: Supported
- **Arbitrum**: Supported
- **Optimism**: Supported
- **Base**: Supported

## Dependencies

- **forge-std**: Foundry standard library
- **account-abstraction**: ERC-4337 reference implementation
- **openzeppelin-contracts**: OpenZeppelin contract library

## Troubleshooting

### Common Issues

**Issue**: `Invalid BLS public key`

- Solution: Ensure public key is 96 bytes compressed G1 point

**Issue**: `Signature verification failed`

- Solution: Check that message point matches signed message hash

**Issue**: `OutOfGas` during verification

- Solution: Increase gas limit based on number of signers

**Issue**: `Node already registered`

- Solution: Each node can only be registered once

## References

- [ERC-4337 Specification](https://eips.ethereum.org/EIPS/eip-4337)
- [EIP-2537 BLS Precompiles](https://eips.ethereum.org/EIPS/eip-2537)
- [Foundry Book](https://book.getfoundry.sh/)
- [BLS12-381 Specification](https://hackmd.io/@benjaminion/bls12-381)

## License

MIT

## Contributing

Contributions are welcome! Please ensure:

- All tests pass
- Code is formatted with `forge fmt`
- Gas optimizations are documented
- Security considerations are addressed

## Support

For issues and questions:

- GitHub Issues: https://github.com/fanhousanbu/YetAnotherAA-Validator/issues
- Main Project: https://github.com/fanhousanbu/YetAnotherAA
