// SuperPaymaster surface the watcher reads, from SP source @ f00be603 (SuperPaymasterStorage.sol
// :218-263, ISuperPaymaster.sol :54-55, SuperPaymasterLens.sol :25, SuperPaymasterAdmin.sol :425).
// Event names are re-checked against SP's pushed 5.5.1 SHA before the watcher ships.
import { ethers } from "ethers";

export const SP_ABI = [
  "event PriceUpdated(int256 indexed price, uint256 indexed timestamp)",
  "event PriceModeChanged(uint8 oldMode, uint8 newMode)",
  "event EmergencyPriceQueued(int256 newPrice, uint256 eta)",
  "event EmergencyPriceExecuted(int256 newPrice)",
  "event EmergencyPriceCancelled(int256 cancelledPrice)",
  "event SlashQueued(address indexed operator)",
  "event SlashCancelled(address indexed operator)",
  "event OperatorSlashed(address indexed operator, uint256 amount, uint8 level)",
  "event ReputationUpdated(address indexed operator, uint256 newScore)",
  "event SlashExecutedWithProof(address indexed operator, uint8 level, uint256 penalty, bytes32 proofHash, uint256 timestamp)",
  "event OperatorPaused(address indexed operator)",
  "event OperatorUnpaused(address indexed operator)",
  "event GlobalPauseSet(address indexed by, bool isPaused)",
  "event GuardianSet(address indexed previousGuardian, address indexed newGuardian)",
  "event BLSAggregatorQueued(address indexed pending, uint48 eta)",
  "event BLSAggregatorUpdated(address indexed oldAggregator, address indexed newAggregator)",
  "event SponsorshipReleased(bytes32 indexed opHash, address indexed operator, uint256 aPNTs)",
  "function cachedPrice() view returns (int256 price, uint256 updatedAt, uint80 roundId, uint8 decimals)",
  "function updatePriceDVT(int256 price, uint256 updatedAt, bytes proof, uint8 chainlinkRecovered)",
];
export const spIface = new ethers.Interface(SP_ABI);
/** Events the watcher scans on the SuperPaymaster proxy (owner/guardian route detection). */
export const SP_WATCHED_EVENTS = [
  "PriceUpdated",
  "PriceModeChanged",
  "EmergencyPriceQueued",
  "EmergencyPriceExecuted",
  "EmergencyPriceCancelled",
  "SlashQueued",
  "SlashCancelled",
  "OperatorSlashed",
  "SlashExecutedWithProof",
  "OperatorPaused",
  "OperatorUnpaused",
  "GlobalPauseSet",
  "GuardianSet",
  "BLSAggregatorQueued",
  "BLSAggregatorUpdated",
];
