from Crypto.Hash import keccak
from ethereum_test_fixtures.blockchain import (
    FixtureHeader,
)
from ethereum_test_forks import Fork, London


HASH_LENGTH = 32

# Offsets for ArbOS-related storage keys
VERSION_OFFSET = 0
UPGRADE_VERSION_OFFSET = 1
UPGRADE_TIMESTAMP_OFFSET = 2
NETWORK_FEE_ACCOUNT_OFFSET = 3
CHAIN_ID_OFFSET = 4
GENESIS_BLOCK_NUM_OFFSET = 5
INFRA_FEE_ACCOUNT_OFFSET = 6
BROTLI_COMPRESSION_LEVEL_OFFSET = 7
NATIVE_TOKEN_ENABLED_FROM_TIME_OFFSET = 8

# ArbOS subspaces
L1_PRICING_SUBSPACE = b"\x00"
L2_PRICING_SUBSPACE = b"\x01"
RETRYABLES_SUBSPACE = b"\x02"
ADDRESS_TABLE_SUBSPACE = b"\x03"
CHAIN_OWNER_SUBSPACE = b"\x04"
SEND_MERKLE_SUBSPACE = b"\x05"
BLOCKHASHES_SUBSPACE = b"\x06"
CHAIN_CONFIG_SUBSPACE = b"\x07"
PROGRAMS_SUBSPACE = b"\x08"
FEATURES_SUBSPACE = b"\x09"
NATIVE_TOKEN_OWNER_SUBSPACE = b"\x0A"

# L2 pricing state offset constants matching Go's iota pattern.
# These are uint64 offsets used for L2 pricing state parameters.
SPEED_LIMIT_PER_SECOND_OFFSET = 0
PER_BLOCK_GAS_LIMIT_OFFSET = 1
BASE_FEE_WEI_OFFSET = 2
MIN_BASE_FEE_WEI_OFFSET = 3
GAS_BACKLOG_OFFSET = 4
PRICING_INERTIA_OFFSET = 5
BACKLOG_TOLERANCE_OFFSET = 6

def mix_digest_with_arbos_version(arbos_version: int) -> bytes:
    digest = bytearray(32)  # initialize 32 zero bytes
    digest[16:24] = arbos_version.to_bytes(8, byteorder="big")
    return bytes(digest)


def enableArbOS(fork: Fork, header: FixtureHeader) -> FixtureHeader:
    if fork >= London:
        header.difficulty = 0x1
        header.extra_data = bytes.fromhex("be7b8b363361b7d39a2bebd539702154ad6b5099d349ece5ee34da671d2a092c")

        match repr(fork):
            case "Shanghai":
                header.prev_randao = mix_digest_with_arbos_version(11)
            case "Cancun":
                header.prev_randao = mix_digest_with_arbos_version(20)
            case "Prague":
                header.prev_randao = mix_digest_with_arbos_version(40)

    return header


class Storage:
    def __init__(self, storage_key: bytes, db=None):
        assert isinstance(storage_key, (bytes, bytearray))
        self.db = db
        self.storage_key = bytes(storage_key)

    @staticmethod
    def keccak256(*parts: bytes) -> bytes:
        """Keccak256 hash of concatenated parts."""
        k = keccak.new(digest_bits=256)
        for p in parts:
            k.update(p)
        return k.digest()

    def map_address(self, key: bytes) -> bytes:
        assert len(key) == HASH_LENGTH
        boundary = HASH_LENGTH - 1
        hashed = self.keccak256(self.storage_key, key[:boundary])
        return hashed[:boundary] + key[boundary:]

    def open_sub_storage(self, id_bytes: bytes) -> "Storage":
        return Storage(
            db=self.db,
            storage_key=self.keccak256(self.storage_key, id_bytes)
        )

    def set(self, key: int, value: int) -> None:
        """
        Set a value in the storage.
        The key is converted to a 32-byte hex string for storage.
        """
        if key < 0:
            raise ValueError("Number must be non-negative")
        if key >= 1 << 256:
            raise ValueError("Number too large for 32 bytes")

        hex_key = "0x" + self.map_address(key.to_bytes(32, byteorder="big")).hex()
        self.db[hex_key] = value


def initialize_l2_pricing_state(storage: Storage) -> None:
    """Initialize the L2 pricing state in the storage."""
    storage.set(SPEED_LIMIT_PER_SECOND_OFFSET, 1000000)
    storage.set(PER_BLOCK_GAS_LIMIT_OFFSET, 20 * 1000000)
    storage.set(BASE_FEE_WEI_OFFSET, int(1e9 / 10))
    storage.set(GAS_BACKLOG_OFFSET, 0)
    storage.set(PRICING_INERTIA_OFFSET, 102)
    storage.set(BACKLOG_TOLERANCE_OFFSET, 10)
    storage.set(MIN_BASE_FEE_WEI_OFFSET, int(1e9 / 10))


def initialize_arbos_state(db: dict, fork: Fork) -> None:
    """
    Initialize ArbOS-related storage, including ArbOS version derived from the selected fork.
    """
    storage = Storage(storage_key=b"", db=db)

    # Map forks to ArbOS versions. Adjust as needed if your spec changes.
    fork_to_arbos_version = {
        "Shanghai": 11,
        "Cancun": 20,
        "Prague": 40,
    }

    # Prefer a stable fork name getter if available: e.g., getattr(fork, "name", str(fork))
    fork_name = repr(fork)
    arbos_version = fork_to_arbos_version.get(fork_name)

    if arbos_version is None:
        # Reasonable default for forks without an explicit mapping.
        # You can also raise if you'd rather be strict.
        arbos_version = 20  # default to Cancun-era ArbOS v20

    storage.set(VERSION_OFFSET, arbos_version)

    # Pricing state uses a separate storage namespace
    initialize_l2_pricing_state(storage.open_sub_storage(L2_PRICING_SUBSPACE))
