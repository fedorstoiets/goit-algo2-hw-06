import hashlib
from typing import Iterable, Any, Dict


class BloomFilter:
    def __init__(self, size: int = 1000, num_hashes: int = 3):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("size must be a positive integer")

        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("num_hashes must be a positive integer")

        self.size = size
        self.num_hashes = num_hashes

        # Compact bit array: 8 bits per byte
        self.bit_array = bytearray((size + 7) // 8)

    def _hashes(self, item: str):
        """
        Generates positions in the Bloom filter.
        The password itself is accepted as a normal string.
        Hashing is used internally by the Bloom filter.
        """
        if not isinstance(item, str):
            raise TypeError("Item must be a string")

        if item == "":
            raise ValueError("Item cannot be empty")

        for i in range(self.num_hashes):
            data = f"{i}:{item}".encode("utf-8")
            digest = hashlib.sha256(data).digest()

            hash_value = int.from_bytes(
                digest[:8],
                byteorder="big"
            )

            yield hash_value % self.size

    def _set_bit(self, position: int):
        byte_index = position // 8
        bit_index = position % 8

        self.bit_array[byte_index] |= 1 << bit_index

    def _get_bit(self, position: int) -> bool:
        byte_index = position // 8
        bit_index = position % 8

        return bool(
            self.bit_array[byte_index] & (1 << bit_index)
        )

    def add(self, item: str):
        for position in self._hashes(item):
            self._set_bit(position)

    def contains(self, item: str) -> bool:
        return all(
            self._get_bit(position)
            for position in self._hashes(item)
        )

    def __contains__(self, item: str) -> bool:
        return self.contains(item)


def check_password_uniqueness(
    bloom_filter: BloomFilter,
    passwords: Iterable[Any]
) -> Dict[str, str]:
    """
    Checks passwords using the provided Bloom filter.

    New unique passwords are also added to the filter,
    so duplicates inside the same input list are detected.
    """

    if not isinstance(bloom_filter, BloomFilter):
        raise TypeError(
            "bloom_filter must be an instance of BloomFilter"
        )

    if isinstance(passwords, (str, bytes)) or not hasattr(
        passwords, "__iter__"
    ):
        raise TypeError("passwords must be an iterable")

    results = {}

    for password in passwords:
        # Incorrect type
        if not isinstance(password, str):
            results[repr(password)] = "некоректний пароль"
            continue

        # Empty password
        if password == "":
            results[password] = "некоректний пароль"
            continue

        if password in bloom_filter:
            results[password] = "вже використаний"
        else:
            results[password] = "унікальний"

            # Remember the newly accepted password
            bloom_filter.add(password)

    return results


if __name__ == "__main__":
    bloom = BloomFilter(
        size=1000,
        num_hashes=3
    )

    existing_passwords = [
        "password123",
        "admin123",
        "qwerty123"
    ]

    for password in existing_passwords:
        bloom.add(password)

    new_passwords_to_check = [
        "password123",
        "newpassword",
        "admin123",
        "guest"
    ]

    results = check_password_uniqueness(
        bloom,
        new_passwords_to_check
    )

    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")