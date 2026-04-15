# YetAnotherAA-Validator

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
A complete BLS signature infrastructure for ERC-4337 account abstraction,
combining off-chain signature aggregation services with on-chain verification
smart contracts.

> **Note**: This package was extracted from the
> [YetAnotherAA](https://github.com/fanhousanbu/YetAnotherAA) monorepo to serve
> as a standalone microservice.

## Components

This repository contains two main components:

1. **Signer Service** (`/` root directory) - Off-chain BLS signature aggregation
   microservice
2. **Validator Contracts** (`/contracts` directory) - On-chain smart contracts
   for signature verification

Both components work together to provide a complete BLS-based signing
infrastructure for ERC-4337 account abstraction.

## Features

### Signer Service Features

- **Individual Node Identity**: Each service instance runs as an independent
  node with unique BLS key pairs
- **BLS12-381 Signatures**: Generate BLS signatures compatible with
  AAStarValidator contract
- **On-chain Registration**: Real blockchain integration for node registration
  using ethers.js
- **RESTful API**: Clean REST endpoints for signature operations and node
  management
- **Gossip Network**: WebSocket-based P2P communication for node discovery
- **Single Port Architecture**: HTTP API and WebSocket gossip on same port
- **Development Ready**: Fixed development nodes for consistent debugging
  experience
- **KMS Integration**: Support for secure key management in production
  environments

### Validator Contract Features

- **BLS Signature Verification**: On-chain verification using EIP-2537
  precompiles
- **Multi-version Support**: Compatible with EntryPoint v0.6, v0.7, and v0.8
- **ERC-4337 Accounts**: Full smart contract wallet implementation
- **Deterministic Deployment**: CREATE2-based account factories
- **Gas Efficient**: Optimized signature verification (~450k gas for 3 signers)

## Architecture

### Complete System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Application                        │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Signer Service (NestJS API)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ Node 1   │  │ Node 2   │  │ Node 3   │  (Gossip Network)│
│  └──────────┘  └──────────┘  └──────────┘                  │
└────────────────────┬────────────────────────────────────────┘
                     │ BLS Signatures
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                Blockchain (Smart Contracts)                  │
│  ┌────────────────────────────────────────────────────┐     │
│  │  AAStarValidator (BLS Verification)                │     │
│  └────────────────────────────────────────────────────┘     │
│  ┌────────────────────────────────────────────────────┐     │
│  │  AAStarAccountFactory (CREATE2 Deployment)         │     │
│  └────────────────────────────────────────────────────┘     │
│  ┌────────────────────────────────────────────────────┐     │
│  │  AAStarAccount (ERC-4337 Wallet)                   │     │
│  └────────────────────────────────────────────────────┘     │
│  ┌────────────────────────────────────────────────────┐     │
│  │  EntryPoint (v0.6 / v0.7 / v0.8)                   │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Signer Service Architecture

Each signer service instance is a stateful node with:

- Unique node ID and BLS key pair
- Local state persistence in `node_*.json` files
- Independent blockchain registration capability
- Self-contained signing operations

### Contract Architecture

- **AAStarValidator**: Manages node registration and signature verification
- **AAStarAccountFactory**: Creates deterministic account addresses
- **AAStarAccount**: ERC-4337 compliant smart contract wallet
- **Multi-version Support**: Separate contracts for v0.6, v0.7, v0.8

## Quick Start

### Step 1: Deploy Smart Contracts

First, deploy the validator contracts (required for signer service):

```bash
cd contracts

# Install Foundry dependencies
forge install

# Deploy validator contract to Sepolia
forge script script/DeployAAStarV7.s.sol:DeployAAStarV7 \
  --rpc-url https://sepolia.infura.io/v3/YOUR_INFURA_KEY \
  --private-key YOUR_PRIVATE_KEY \
  --broadcast \
  --legacy

# Note the deployed VALIDATOR_CONTRACT_ADDRESS
```

For detailed contract deployment instructions, see
[contracts/README.md](contracts/README.md).

### Step 2: Configure Signer Service

Create a `.env` file based on `.env.example`:

```bash
# Node Configuration
NODE_STATE_FILE=./node_dev_001.json
PORT=3001

# Gossip Network Configuration (Optional)
GOSSIP_PUBLIC_URL=ws://localhost:3001/ws
GOSSIP_BOOTSTRAP_PEERS=ws://localhost:3002/ws,ws://localhost:3003/ws

# Blockchain Configuration
VALIDATOR_CONTRACT_ADDRESS=0xYourValidatorContractAddress
ETH_RPC_URL=https://sepolia.infura.io/v3/YOUR_INFURA_API_KEY
ETH_PRIVATE_KEY=YOUR_PRIVATE_KEY_HERE

# KMS Configuration (Production)
KMS_ENABLED=false
KMS_ENDPOINT=https://kms.aastar.io
```

### Step 3: Start Signer Service

```bash
# Return to root directory
cd ..

# Install dependencies
npm install

# Build the project
npm run build

# Start development server
npm run start:dev

# Start production server
npm run start:prod
```

### Development with Multiple Nodes

Three fixed development nodes are provided for consistent debugging:

- **node_dev_001.json**: Port 3001, Node ID `0x123e4567e89b12d3a456426614174001`
- **node_dev_002.json**: Port 3002, Node ID `0x123e4567e89b12d3a456426614174002`
- **node_dev_003.json**: Port 3003, Node ID `0x123e4567e89b12d3a456426614174003`

Start multiple nodes:

```bash
# Terminal 1
NODE_STATE_FILE=./node_dev_001.json PORT=3001 npm run start:dev

# Terminal 2
NODE_STATE_FILE=./node_dev_002.json PORT=3002 npm run start:dev

# Terminal 3
NODE_STATE_FILE=./node_dev_003.json PORT=3003 npm run start:dev
```

## API Endpoints

### Node Management

- `GET /node/info` - Get current node information
- `POST /node/register` - Register node on AAStarValidator contract

### Signature Operations

- `POST /signature/sign` - Generate BLS signature for message
- `POST /signature/aggregate` - Aggregate external signatures from multiple
  nodes

### Gossip Network

- `GET /gossip/peers` - Get active gossip peers
- `GET /gossip/stats` - Get gossip network statistics
- `WS /ws` - WebSocket gossip protocol endpoint

### Documentation

- `GET /api` - Swagger API documentation

## Node Startup Modes

The service supports three initialization modes:

### 1. Specific Node ID (Highest Priority)

```bash
NODE_ID=0x123e4567e89b12d3a456426614174001 npm start
```

### 2. State File Path

```bash
NODE_STATE_FILE=/path/to/node_state.json npm start
```

### 3. Auto Discovery (Default)

```bash
npm start  # Discovers existing node files automatically
```

## Blockchain Integration

### On-chain Registration

The `/node/register` endpoint performs real blockchain transactions:

1. Check if node is already registered via `isRegistered()`
2. Call `registerPublicKey()` on AAStarValidator contract
3. Wait for transaction confirmation
4. Update local node state

### Requirements

- Contract owner private key (`ETH_PRIVATE_KEY`)
- Sufficient ETH balance for gas fees
- Valid RPC endpoint (`ETH_RPC_URL`)

### Response Example

```json
{
  "success": true,
  "message": "Node registered successfully on-chain",
  "nodeId": "0x123e4567e89b12d3a456426614174001",
  "txHash": "0x1234...abcd",
  "contractAddress": "0xAe7eA28a0aeA05cbB8631bDd7B10Cb0f387FC479"
}
```

## Repository Structure

```
YetAnotherAA-Validator/
├── src/                           # Signer service source code
│   ├── interfaces/                # TypeScript interfaces
│   ├── modules/
│   │   ├── bls/                  # BLS cryptography operations
│   │   ├── blockchain/           # Ethereum contract interactions
│   │   ├── gossip/               # WebSocket gossip network
│   │   ├── node/                 # Node identity and state management
│   │   └── signature/            # Signature generation services
│   ├── utils/                    # BLS utilities and helpers
│   └── main.ts                   # Application entry point
├── contracts/                     # Smart contract directory
│   ├── src/                      # Solidity contracts
│   │   ├── AAStarValidator.sol   # BLS signature verification
│   │   ├── AAStarAccount*.sol    # ERC-4337 accounts (v0.6/v0.7/v0.8)
│   │   └── AAStarAccountFactory*.sol  # Account factories
│   ├── script/                   # Deployment scripts
│   ├── test/                     # Contract tests
│   ├── lib/                      # Foundry dependencies
│   └── README.md                 # Contract documentation
├── data/                         # Node data directory
├── package.json                  # NPM package configuration
├── README.md                     # This file
└── LICENSE                       # Apache License 2.0

node_dev_*.json         # Development node state files (contain private keys)
node_*.json             # Dynamic node files (ignored by git)
```

## Security

- Private keys are never exposed in API responses
- Node state files contain sensitive keys and should be protected
- **IMPORTANT**: All `node_*.json` files contain private keys and are excluded
  from git
- Development node files should be regenerated for your environment
- Production deployments should use KMS for key management

## Signature Aggregation Workflow

The aggregation system follows a distributed workflow where nodes operate
independently:

### 1. Individual Node Signing

Each node signs messages independently:

```bash
curl -X POST http://localhost:3001/signature/sign \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello World"}'
```

Response:

```json
{
  "nodeId": "0xf26f8bdca182790bad5481c1f0eac3e7ffb135ab33037dd02b8d98a1066c6e5d",
  "signature": "afc696360a866979fb4b4e6757af4d1621616b5d928061be5aa2243c0b8ded9b...",
  "publicKey": "8052464ad7afdeaa9416263fb0eb72925b77957796973ecb7fcda5d4fc733c4a...",
  "message": "Hello World"
}
```

### 2. Central Collection

A central coordinator collects signatures from multiple nodes. Each node only
knows about itself, not other nodes.

### 3. Signature Aggregation

Any node can aggregate the collected external signatures. BLS aggregation
requires signatures and their corresponding public keys:

```bash
curl -X POST http://localhost:3001/signature/aggregate \
  -H "Content-Type: application/json" \
  -d '{
    "signatures": [
      {
        "nodeId": "0x123e4567e89b12d3a456426614174001",
        "signature": "0xafc696360a866979fb4b4e6757af4d1621616b5d928061be5aa2243c0b8ded9b...",
        "publicKey": "0x8052464ad7afdeaa9416263fb0eb72925b77957796973ecb7fcda5d4fc733c4a..."
      },
      {
        "nodeId": "0x123e4567e89b12d3a456426614174002",
        "signature": "0xdef789abc123456789def123456789abc456789def123456789def123456789...",
        "publicKey": "0x9876543210fedcbafedcba0987654321098765432109876543210987654321..."
      }
    ]
  }'
```

Response:

```json
{
  "nodeIds": [
    "0x123e4567e89b12d3a456426614174001",
    "0x123e4567e89b12d3a456426614174002"
  ],
  "aggregateSignature": "0x000000000000000000000000000000000b74054fd1bd02d6f1d83d35c472490c...",
  "aggregatePublicKey": "0x000000000000000000000000000000000052464ad7afdeaa9416263fb0eb72925b..."
}
```

### Key Properties

- **Efficient BLS Aggregation**: Aggregates signatures and public keys using
  BLS12-381 mathematics
- **Stateless Operation**: Nodes don't need access to other nodes' private keys
  or registration data
- **Flexible Coordination**: Any node can perform aggregation with provided
  external signatures
- **Complete Output**: Returns both aggregated signature and aggregated public
  key
- **EIP-2537 Format**: All outputs are formatted for direct use with
  AAStarValidator contract

## Production Deployment

### KMS Integration

For production environments, enable KMS to manage private keys securely:

```bash
KMS_ENABLED=true
KMS_ENDPOINT=https://your-kms-endpoint.com
```

### Multi-Node Setup

Deploy at least 3 nodes for redundancy:

1. Each node should have its own `NODE_STATE_FILE`
2. Configure `GOSSIP_BOOTSTRAP_PEERS` to point to other nodes
3. Ensure all nodes are registered on-chain
4. Load balance API requests across nodes

### Environment Best Practices

- Use environment variables instead of `.env` files
- Secure `node_*.json` files with proper file permissions
- Enable HTTPS for production API endpoints
- Use WebSocket secure (wss://) for gossip network

## Development

### Available Scripts

- `npm run build` - Build the project
- `npm run start` - Start production server
- `npm run start:dev` - Start development server with watch mode
- `npm run start:debug` - Start with debugging enabled
- `npm run lint` - Run ESLint
- `npm run lint:check` - Check linting without fixing
- `npm run format` - Format code with Prettier
- `npm run format:check` - Check formatting
- `npm run test` - Run tests
- `npm run test:ci` - Run tests in CI mode
- `npm run type-check` - TypeScript type checking

### Demo Tool

A complete ERC-4337 + BLS transfer tool is available in the `demo/` directory:

- **`demo/main.js`** - Complete transfer tool with integrated BLS signing
- **`demo/config.example.json`** - Configuration template for setup
- **`demo/README.md`** - Setup and usage instructions

## Contract Compatibility

Compatible with AAStarValidator contract functions:

- `registerPublicKey(bytes32 nodeId, bytes calldata publicKey)`
- `isRegistered(bytes32 nodeId) returns (bool)`
- `verifyAggregateSignature(...)` - via signature generation endpoints

## Key Technologies

### Signer Service

- **Framework**: NestJS
- **Cryptography**: BLS12-381 (@noble/curves), @noble/hashes
- **Blockchain**: Ethers.js v6
- **Network**: WebSocket (ws), Axios
- **Validation**: class-validator, class-transformer
- **API Docs**: Swagger/OpenAPI

### Smart Contracts

- **Development**: Foundry (Forge, Anvil, Cast)
- **Language**: Solidity ^0.8.23
- **Standards**: ERC-4337, EIP-2537
- **Dependencies**: OpenZeppelin, account-abstraction

## Integration with YetAnotherAA

This signer service is designed to work with:

- **AAStarValidator**: Smart contract for BLS signature verification
- **AAStarAccountFactory**: ERC-4337 account factory
- **EntryPoint v0.6/v0.7/v0.8**: ERC-4337 entry points

For the complete account abstraction stack, see the main
[YetAnotherAA](https://github.com/fanhousanbu/YetAnotherAA) repository.

## License

Licensed under the [Apache License, Version 2.0](https://opensource.org/licenses/Apache-2.0). See [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions:

- GitHub Issues: https://github.com/fanhousanbu/YetAnotherAA-Validator/issues
- Main Project: https://github.com/fanhousanbu/YetAnotherAA
