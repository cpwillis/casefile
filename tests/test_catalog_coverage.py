from casefile.catalog import load_catalog, sources_for
from casefile.types import EntityType

# The 1.0.0 bar was 250, but six of those slots were the same URL listed twice under two names,
# which was never coverage. Re-based once the loader started rejecting duplicate URLs.
MINIMUM_SLOTS = 240
FLOOR_PER_TYPE = 3
EXEMPT = {EntityType.USERNAME}  # WhatsMyName covers username, so it needs no catalogue floor


def test_every_type_has_a_floor_of_sources():
    catalog = load_catalog()
    thin = {
        t.value: len(sources_for(catalog, t))
        for t in EntityType
        if t not in EXEMPT and len(sources_for(catalog, t)) < FLOOR_PER_TYPE
    }
    assert not thin, f"types below {FLOOR_PER_TYPE} sources: {thin}"


def test_total_slot_coverage():
    catalog = load_catalog()
    slots = sum(len(s.accepts) for s in catalog)
    assert slots >= MINIMUM_SLOTS, f"{slots} slots, need {MINIMUM_SLOTS}"
