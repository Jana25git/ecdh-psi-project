from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass
from typing import Dict, Iterable, List, Set, Tuple

from tinyec import registry
from tinyec.ec import Point


# ============================================================
# Configuration
# ============================================================

# You can change the curve if your instructor wants another one.
CURVE = registry.get_curve("secp384r1")  # strong ECC curve example
HASH_NAME = "sha384"                     # strong hash example


# ============================================================
# Utility functions
# ============================================================

def hash_bytes(data: bytes) -> bytes:
    """Return digest bytes using the selected hash."""
    h = hashlib.new(HASH_NAME)
    h.update(data)
    return h.digest()


def hash_text(text: str) -> bytes:
    """Hash a string into bytes."""
    return hash_bytes(text.encode("utf-8"))


def hash_to_scalar(text: str, modulus: int) -> int:
    """
    Educational shortcut:
    map text -> scalar in [1, modulus-1].

    Note:
    This is NOT a full RFC hash-to-curve construction.
    For a class project prototype, this is often acceptable.
    """
    value = int.from_bytes(hash_text(text), "big") % modulus
    return value if value != 0 else 1


def hash_to_point(text: str) -> Point:
    """
    Map an element x to a curve point H(x) by hashing to a scalar h
    and computing h*G.
    """
    h = hash_to_scalar(text, CURVE.field.n)
    return h * CURVE.g


def encode_point(point: Point) -> bytes:
    """
    Serialize a point into bytes for hashing/comparison.
    """
    x_bytes = point.x.to_bytes((point.x.bit_length() + 7) // 8, "big")
    y_bytes = point.y.to_bytes((point.y.bit_length() + 7) // 8, "big")
    return b"\x04" + x_bytes + b"|" + y_bytes


def point_commitment(point: Point) -> str:
    """
    Commitment = Hash(serialized_point).
    """
    return hashlib.new(HASH_NAME, encode_point(point)).hexdigest()


def random_private_key() -> int:
    """
    Generate private scalar in [1, n-1].
    """
    n = CURVE.field.n
    return secrets.randbelow(n - 1) + 1


# ============================================================
# Simple Bloom Filter
# ============================================================

class BloomFilter:
    def __init__(self, size: int, num_hashes: int) -> None:
        self.size = size
        self.num_hashes = num_hashes
        self.bits = [0] * size

    def _positions(self, item: str) -> List[int]:
        positions = []
        for i in range(self.num_hashes):
            data = f"{i}:{item}".encode("utf-8")
            digest = hashlib.sha256(data).digest()
            pos = int.from_bytes(digest, "big") % self.size
            positions.append(pos)
        return positions

    def add(self, item: str) -> None:
        for pos in self._positions(item):
            self.bits[pos] = 1

    def __contains__(self, item: str) -> bool:
        return all(self.bits[pos] == 1 for pos in self._positions(item))


def build_bloom_filter(items: Iterable[str], false_positive_rate: float = 0.01) -> BloomFilter:
    items = list(items)
    n = max(len(items), 1)

    # Standard Bloom filter formulas
    m = max(8, int(-(n * math.log(false_positive_rate)) / (math.log(2) ** 2)))
    k = max(1, int((m / n) * math.log(2)))

    bloom = BloomFilter(size=m, num_hashes=k)
    for item in items:
        bloom.add(item)
    return bloom


# ============================================================
# Party model
# ============================================================

@dataclass
class Party:
    name: str
    private_set: Set[str]
    private_key: int

    def first_computation(self, items: Iterable[str]) -> Dict[str, Point]:
        """
        Compute aH(x) or bH(y).
        """
        result: Dict[str, Point] = {}
        for item in items:
            Hx = hash_to_point(item)
            result[item] = self.private_key * Hx
        return result

    def commitments(self, transformed: Dict[str, Point]) -> Dict[str, str]:
        """
        Compute Hash(aH(x)) or Hash(bH(y)).
        """
        return {item: point_commitment(pt) for item, pt in transformed.items()}

    def verify_commitments(self, transformed: Dict[str, Point], commitments: Dict[str, str]) -> bool:
        """
        Verify received commitments.
        """
        for item, pt in transformed.items():
            expected = point_commitment(pt)
            received = commitments.get(item)
            if received != expected:
                return False
        return True

    def double_computation(self, received_points: Dict[str, Point]) -> Dict[str, Point]:
        """
        Compute a(bH(y)) or b(aH(x)).
        """
        return {item: self.private_key * pt for item, pt in received_points.items()}


# ============================================================
# ECDH-PSI Protocol
# ============================================================

def ecdh_psi_protocol(set_a: Set[str], set_b: Set[str]) -> Tuple[Set[str], Dict[str, object]]:
    """
    Educational prototype matching your diagram:

    1. A builds Bloom filter from S_A and sends it to B.
    2. B filters S_B -> S'_B.
    3. A computes aH(x), x in S_A.
    4. B computes bH(y), y in S'_B.
    5. Both compute commitments.
    6. Verify commitments.
    7. A computes a(bH(y)).
    8. B computes b(aH(x)).
    9. Compare results and output S_A ∩ S_B.
    """

    # Parties
    A = Party(name="A", private_set=set_a, private_key=random_private_key())
    B = Party(name="B", private_set=set_b, private_key=random_private_key())

    # Step 1: A builds Bloom filter from S_A
    bloom_a = build_bloom_filter(A.private_set)

    # Step 2: B filters S_B using Bloom filter -> S'_B
    filtered_b = {item for item in B.private_set if item in bloom_a}

    # Step 3: A computes aH(x), x ∈ S_A
    A_first = A.first_computation(A.private_set)

    # Step 4: B computes bH(y), y ∈ S'_B
    B_first = B.first_computation(filtered_b)

    # Step 5: commitments
    A_commit = A.commitments(A_first)
    B_commit = B.commitments(B_first)

    # Step 6: verify commitments
    if not B.verify_commitments(A_first, A_commit):
        raise ValueError("Abort: A's commitments are invalid.")
    if not A.verify_commitments(B_first, B_commit):
        raise ValueError("Abort: B's commitments are invalid.")

    # Step 7: A computes a(bH(y))
    A_double = A.double_computation(B_first)

    # Step 8: B computes b(aH(x))
    B_double = B.double_computation(A_first)

    # Step 9: compare results
    # Encode points so they can be compared as dictionary keys
    A_double_encoded = {item: encode_point(pt) for item, pt in A_double.items()}
    B_double_encoded = {item: encode_point(pt) for item, pt in B_double.items()}

    common_encodings = set(A_double_encoded.values()) & set(B_double_encoded.values())

    # Recover matching elements
    intersection_from_a = {item for item, enc in B_double_encoded.items() if enc in common_encodings}
    intersection_from_b = {item for item, enc in A_double_encoded.items() if enc in common_encodings}

    # For a correct PSI run, both should refer to the same logical shared items
    intersection = intersection_from_a & intersection_from_b

    debug_info = {
        "curve": CURVE.name,
        "hash": HASH_NAME,
        "A_private_key": A.private_key,
        "B_private_key": B.private_key,
        "S_A": A.private_set,
        "S_B": B.private_set,
        "S_B_filtered": filtered_b,
        "A_commitments": A_commit,
        "B_commitments": B_commit,
        "A_first_count": len(A_first),
        "B_first_count": len(B_first),
        "A_double_count": len(A_double),
        "B_double_count": len(B_double),
    }

    return intersection, debug_info


# ============================================================
# Example run
# ============================================================

if __name__ == "__main__":
    S_A = {
        "alice@example.com",
        "bob@example.com",
        "carol@example.com",
        "dave@example.com",
    }

    S_B = {
        "carol@example.com",
        "eve@example.com",
        "bob@example.com",
        "mallory@example.com",
    }

    intersection, info = ecdh_psi_protocol(S_A, S_B)

    print("=== ECDH-PSI Result ===")
    print("Intersection:", intersection)
    print()
    print("=== Debug Info ===")
    for k, v in info.items():
        print(f"{k}: {v}")