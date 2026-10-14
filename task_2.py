import json
import hashlib
import ipaddress
import math
import time


class HyperLogLog:
    def __init__(self, p: int = 14):
        """
        p controls the number of registers.

        m = 2^p

        p=14 gives 16384 registers and good accuracy
        while using little memory.
        """

        if not isinstance(p, int) or not 4 <= p <= 16:
            raise ValueError(
                "p must be an integer between 4 and 16"
            )

        self.p = p
        self.m = 1 << p

        # One byte per register
        self.registers = bytearray(self.m)

    def add(self, value: str):
        if not isinstance(value, str):
            raise TypeError("HyperLogLog value must be a string")

        # Produce a stable 64-bit hash
        digest = hashlib.sha1(
            value.encode("utf-8")
        ).digest()

        hash_value = int.from_bytes(
            digest[:8],
            byteorder="big"
        )

        # First p bits determine register index
        index = hash_value >> (64 - self.p)

        # Remaining bits determine rank
        remaining_bits_count = 64 - self.p

        remaining = hash_value & (
            (1 << remaining_bits_count) - 1
        )

        if remaining == 0:
            rank = remaining_bits_count + 1
        else:
            rank = (
                remaining_bits_count
                - remaining.bit_length()
                + 1
            )

        self.registers[index] = max(
            self.registers[index],
            rank
        )

    def count(self) -> float:
        m = self.m

        if m == 16:
            alpha = 0.673
        elif m == 32:
            alpha = 0.697
        elif m == 64:
            alpha = 0.709
        else:
            alpha = 0.7213 / (1 + 1.079 / m)

        harmonic_sum = sum(
            2.0 ** (-register)
            for register in self.registers
        )

        estimate = (
            alpha
            * m
            * m
            / harmonic_sum
        )

        # Small-range correction
        empty_registers = self.registers.count(0)

        if (
            estimate <= 2.5 * m
            and empty_registers > 0
        ):
            estimate = (
                m
                * math.log(
                    m / empty_registers
                )
            )

        return estimate


def iter_ip_addresses(file_path: str):
    """
    Reads the log file line by line.

    Invalid JSON records, missing IP addresses and
    invalid IP addresses are ignored.
    """

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

                ip = record.get("remote_addr")

                if not isinstance(ip, str) or not ip:
                    continue

                # Validate IPv4 / IPv6
                ipaddress.ip_address(ip)

                yield ip

            except (
                json.JSONDecodeError,
                ValueError,
                TypeError
            ):
                # Ignore incorrect records
                continue


def exact_unique_count(file_path: str) -> int:
    unique_ips = set()

    for ip in iter_ip_addresses(file_path):
        unique_ips.add(ip)

    return len(unique_ips)


def hyperloglog_unique_count(
    file_path: str,
    p: int = 14
) -> float:
    hll = HyperLogLog(p=p)

    for ip in iter_ip_addresses(file_path):
        hll.add(ip)

    return hll.count()


def benchmark(file_path: str):
    # Exact counting
    start = time.perf_counter()

    exact_result = exact_unique_count(
        file_path
    )

    exact_time = (
        time.perf_counter() - start
    )

    # HyperLogLog
    start = time.perf_counter()

    hll_result = hyperloglog_unique_count(
        file_path
    )

    hll_time = (
        time.perf_counter() - start
    )

    error_percent = (
        abs(hll_result - exact_result)
        / exact_result
        * 100
        if exact_result
        else 0
    )

    print("\nРезультати порівняння:")
    print("-" * 68)

    print(
        f"{'':32}"
        f"{'Точний підрахунок':>18}"
        f"{'HyperLogLog':>18}"
    )

    print("-" * 68)

    print(
        f"{'Унікальні елементи':32}"
        f"{exact_result:>18.1f}"
        f"{hll_result:>18.1f}"
    )

    print(
        f"{'Час виконання (сек.)':32}"
        f"{exact_time:>18.6f}"
        f"{hll_time:>18.6f}"
    )

    print("-" * 68)

    print(
        f"Похибка HyperLogLog: "
        f"{error_percent:.3f}%"
    )


if __name__ == "__main__":
    LOG_FILE = "lms-stage-access.log"

    benchmark(LOG_FILE)