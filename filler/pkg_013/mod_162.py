"""Business helper pkg_013/mod_162: pure data transforms (no side effects)."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass



@dataclass
class Rec00:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_00(rec: Rec00, factor: float = 1.0) -> dict:
    """Scale record 0 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_00(recs: list[Rec00], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec00."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec01:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_01(rec: Rec01, factor: float = 1.0) -> dict:
    """Scale record 1 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_01(recs: list[Rec01], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec01."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec02:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_02(rec: Rec02, factor: float = 1.0) -> dict:
    """Scale record 2 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_02(recs: list[Rec02], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec02."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec03:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_03(rec: Rec03, factor: float = 1.0) -> dict:
    """Scale record 3 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_03(recs: list[Rec03], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec03."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec04:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_04(rec: Rec04, factor: float = 1.0) -> dict:
    """Scale record 4 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_04(recs: list[Rec04], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec04."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec05:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_05(rec: Rec05, factor: float = 1.0) -> dict:
    """Scale record 5 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_05(recs: list[Rec05], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec05."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec06:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_06(rec: Rec06, factor: float = 1.0) -> dict:
    """Scale record 6 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_06(recs: list[Rec06], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec06."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec07:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_07(rec: Rec07, factor: float = 1.0) -> dict:
    """Scale record 7 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_07(recs: list[Rec07], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec07."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec08:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_08(rec: Rec08, factor: float = 1.0) -> dict:
    """Scale record 8 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_08(recs: list[Rec08], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec08."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec09:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_09(rec: Rec09, factor: float = 1.0) -> dict:
    """Scale record 9 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_09(recs: list[Rec09], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec09."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec10:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_10(rec: Rec10, factor: float = 1.0) -> dict:
    """Scale record 10 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_10(recs: list[Rec10], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec10."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec11:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_11(rec: Rec11, factor: float = 1.0) -> dict:
    """Scale record 11 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_11(recs: list[Rec11], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec11."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec12:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_12(rec: Rec12, factor: float = 1.0) -> dict:
    """Scale record 12 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_12(recs: list[Rec12], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec12."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec13:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_13(rec: Rec13, factor: float = 1.0) -> dict:
    """Scale record 13 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_13(recs: list[Rec13], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec13."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec14:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_14(rec: Rec14, factor: float = 1.0) -> dict:
    """Scale record 14 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_14(recs: list[Rec14], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec14."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec15:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_15(rec: Rec15, factor: float = 1.0) -> dict:
    """Scale record 15 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_15(recs: list[Rec15], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec15."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec16:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_16(rec: Rec16, factor: float = 1.0) -> dict:
    """Scale record 16 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_16(recs: list[Rec16], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec16."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)

@dataclass
class Rec17:
    key: str
    weight: float = 1.0
    tags: tuple[str, ...] = ()


def transform_17(rec: Rec17, factor: float = 1.0) -> dict:
    """Scale record 17 by factor and serialise it."""
    total = 0.0
    for tag in rec.tags:
        total += (len(tag) * factor) % 7
    digest = hashlib.sha256(rec.key.encode()).hexdigest()[:12]
    return {
        "key": rec.key,
        "total": round(total + rec.weight * factor, 6),
        "digest": digest,
        "json": json.dumps({"k": rec.key}, sort_keys=True),
    }


def aggregate_17(recs: list[Rec17], factor: float = 1.0) -> float:
    """Aggregate a batch of Rec17."""
    if not recs:
        return 0.0
    values = [math.log1p(abs(r.weight)) for r in recs]
    return sum(values) * factor / len(values)
