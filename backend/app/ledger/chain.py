"""Blockchain audit ledger — in-memory list mirrored to LedgerBlock DB table.

Hash formula:
  block_hash = SHA256(prev_hash + json.dumps(payload, sort_keys=True, default=str) + created_at.isoformat())
"""

import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ledger_block import LedgerBlock

logger = logging.getLogger(__name__)


class BlockchainLedger:
    def __init__(self) -> None:
        self._chain: list[LedgerBlock] = []

    @property
    def block_count(self) -> int:
        return len(self._chain)

    @staticmethod
    def _compute_hash(prev_hash: str, payload: dict, created_at: datetime) -> str:
        raw = (
            prev_hash
            + json.dumps(payload, sort_keys=True, default=str)
            + created_at.isoformat()
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    async def load_from_db(self, db: AsyncSession) -> None:
        result = await db.execute(
            select(LedgerBlock).order_by(LedgerBlock.id.asc())
        )
        self._chain = list(result.scalars().all())
        logger.info("Loaded %d ledger blocks from DB", len(self._chain))

    async def append(
        self,
        event_type: str,
        entity_id: str | None,
        payload: dict,
        db: AsyncSession,
    ) -> LedgerBlock:
        prev_hash = self._chain[-1].block_hash if self._chain else "0" * 64
        now = datetime.now(timezone.utc)
        block_hash = self._compute_hash(prev_hash, payload, now)

        block = LedgerBlock(
            block_hash=block_hash,
            prev_hash=prev_hash,
            event_type=event_type,
            entity_id=entity_id,
            payload=payload,
        )
        block.created_at = now  # required for hash verification
        db.add(block)
        await db.flush()

        self._chain.append(block)
        return block

    async def verify_chain(self) -> dict:
        if not self._chain:
            return {"valid": True, "block_count": 0, "first_invalid_block": None}

        for i, block in enumerate(self._chain):
            if i == 0:
                expected_prev = "0" * 64
            else:
                expected_prev = self._chain[i - 1].block_hash

            if block.prev_hash != expected_prev:
                return {
                    "valid": False,
                    "block_count": len(self._chain),
                    "first_invalid_block": block.id,
                }

            expected_hash = self._compute_hash(
                block.prev_hash, block.payload, block.created_at
            )
            if block.block_hash != expected_hash:
                return {
                    "valid": False,
                    "block_count": len(self._chain),
                    "first_invalid_block": block.id,
                }

        return {
            "valid": True,
            "block_count": len(self._chain),
            "first_invalid_block": None,
        }


ledger = BlockchainLedger()
