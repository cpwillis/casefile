"""Entity taxonomy. Imported by everything; imports nothing."""

from dataclasses import dataclass
from enum import StrEnum


class EntityType(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    ASN = "asn"
    URL = "url"
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    COMPANY = "company"
    PHONE = "phone"
    HASH = "hash"
    CVE = "cve"
    BTC_ADDRESS = "btc_address"
    ETH_ADDRESS = "eth_address"
    TX_HASH = "tx_hash"
    COORDINATES = "coordinates"
    MAC = "mac"
    VIN = "vin"
    MMSI = "mmsi"
    IMO = "imo"
    ICAO24 = "icao24"
    TAIL_NUMBER = "tail_number"


@dataclass(frozen=True, slots=True)
class Candidate:
    """One plausible reading of the input, with the value normalised for that reading."""

    type: EntityType
    value: str
