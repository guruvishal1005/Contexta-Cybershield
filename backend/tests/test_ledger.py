"""Blockchain ledger integrity tests."""

import pytest
from datetime import datetime, timezone

from app.ledger.chain import BlockchainLedger
from app.models.ledger_block import LedgerBlock


class FakeDB:
    """Minimal mock that satisfies the ledger's db.add() and db.flush() calls."""

    def __init__(self):
        self._id_counter = 0
        self.added = []

    def add(self, obj):
        self._id_counter += 1
        obj.id = self._id_counter
        if not getattr(obj, "created_at", None):
            obj.created_at = datetime.now(timezone.utc)
        self.added.append(obj)

    async def flush(self):
        pass


@pytest.fixture
def fresh_ledger():
    return BlockchainLedger()


@pytest.fixture
def fake_db():
    return FakeDB()


@pytest.mark.asyncio
async def test_append_five_blocks_and_verify(fresh_ledger, fake_db):
    for i in range(5):
        await fresh_ledger.append(
            event_type=f"test_event_{i}",
            entity_id=f"entity-{i}",
            payload={"step": i},
            db=fake_db,
        )

    assert fresh_ledger.block_count == 5
    result = await fresh_ledger.verify_chain()
    assert result["valid"] is True
    assert result["block_count"] == 5
    assert result["first_invalid_block"] is None


@pytest.mark.asyncio
async def test_tampered_block_detected(fresh_ledger, fake_db):
    for i in range(5):
        await fresh_ledger.append(
            event_type=f"event_{i}",
            entity_id=None,
            payload={"data": i},
            db=fake_db,
        )

    # Tamper with block 3's payload
    fresh_ledger._chain[2].payload = {"data": "TAMPERED"}

    result = await fresh_ledger.verify_chain()
    assert result["valid"] is False
    assert result["first_invalid_block"] == fresh_ledger._chain[2].id
