import hashlib
from typing import Any, Dict, Iterable


class BloomFilter:
    def __init__(self, size: int = 1000, num_hashes: int = 3):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("size must be a positive integer")

        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("num_hashes must be a positive integer")

        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bytearray((size + 7) // 8)

    def _hashes(self, item: str):
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
) -> Dict[Any, str]:
    """
    Перевіряє список паролів на унікальність.

    Некоректні значення (None, числа, порожні рядки)
    безпечно позначаються як некоректні й не передаються
    до Bloom Filter.
    """

    if not isinstance(bloom_filter, BloomFilter):
        raise TypeError(
            "bloom_filter must be an instance of BloomFilter"
        )

    if isinstance(passwords, (str, bytes)):
        raise TypeError(
            "passwords must be an iterable of password values"
        )

    try:
        iterator = iter(passwords)
    except TypeError as exc:
        raise TypeError(
            "passwords must be an iterable"
        ) from exc

    results = {}

    for password in iterator:
        # Validation requested by mentor
        if password is None:
            results[password] = "некоректний пароль"
            continue

        if not isinstance(password, str):
            results[password] = "некоректний пароль"
            continue

        if password == "":
            results[password] = "некоректний пароль"
            continue

        if password in bloom_filter:
            results[password] = "вже використаний"
        else:
            results[password] = "унікальний"
            bloom_filter.add(password)

    return results


if __name__ == "__main__":
    bloom = BloomFilter(size=1000, num_hashes=3)

    existing_passwords = [
        "password123",
        "admin123",
        "qwerty123"
    ]

    for password in existing_passwords:
        bloom.add(password)

    # Основний приклад із завдання
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

    # Додаткова перевірка валідації
    print("\nПеревірка некоректних значень:")

    invalid_passwords = [
        None,
        12345,
        "",
        "another_password"
    ]

    validation_results = check_password_uniqueness(
        bloom,
        invalid_passwords
    )

    for password, status in validation_results.items():
        print(f"Пароль {repr(password)} — {status}.")