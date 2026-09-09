"""Solo integer-accounting oracle, NOT blockchain/cryptography software.

Scope: one validator pool, pooled public totals, deposits, integer shares,
commission, slashing, fee-from-release and dual-bound exit claims.
Not modelled: keys/proofs, actual ABCI, async slash jobs, multiple validators,
network trust, disk durability, wallet recovery, actual time source.
Python integers are a readable oracle; Rust must use checked U128/U256.
"""
from __future__ import annotations
from dataclasses import dataclass
from copy import deepcopy
from functools import wraps
from typing import Callable

MAX_AMOUNT = 2**120
DEFAULT_CAP = 10**26

class ModelError(ValueError):
    pass

def amount(x: int) -> int:
    if type(x) is not int or not 0 <= x < MAX_AMOUNT:
        raise ModelError("amount outside [0,2^120)")
    return x

def ratio(x: int, bps: int) -> int:
    amount(x)
    if type(bps) is not int or not 0 <= bps <= 10_000:
        raise ModelError("invalid basis points")
    return x * bps // 10_000

def emission(supply: int, carry: int = 0, epoch_blocks: int = 720,
             bps: int = 200, year_blocks: int = 6_307_200) -> tuple[int, int]:
    amount(supply)
    if year_blocks <= 0 or epoch_blocks <= 0 or not 0 <= bps <= 10_000:
        raise ModelError("invalid emission parameters")
    denominator = 10_000 * year_blocks
    if type(carry) is not int or not 0 <= carry < denominator:
        raise ModelError("invalid fractional carry")
    return divmod(supply * bps * epoch_blocks + carry, denominator)

def share_quote(assets: int, shares: int, deposit: int) -> int:
    amount(assets); amount(shares); amount(deposit)
    if deposit == 0:
        raise ModelError("zero deposit")
    if assets == 0 and shares == 0:
        return deposit
    if assets == 0 or shares == 0:
        raise ModelError("inconsistent or insolvent generation")
    result = deposit * shares // assets
    if result == 0:
        raise ModelError("deposit mints zero shares")
    return amount(result)

def redeem_quote(assets: int, shares: int, burn: int) -> int:
    amount(assets); amount(shares); amount(burn)
    if not 0 < burn <= shares:
        raise ModelError("invalid burn")
    return assets if burn == shares else burn * assets // shares

def atomic(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        before = deepcopy(self.__dict__)
        try:
            result = fn(self, *args, **kwargs)
            self.check()
            return result
        except Exception:
            self.__dict__.clear()
            self.__dict__.update(before)
            raise
    return wrapped

@dataclass
class Cohort:
    assets: int = 0
    shares: int = 0
    exposure_end_height: int = 0
    exposure_end_time: int = 0
    matured: bool = False

@dataclass
class Ticket:
    position: str
    cohort: int
    units: int
    claimed: bool = False

class Ledger:
    def __init__(self, genesis: int = 10**12, cap: int = DEFAULT_CAP):
        amount(genesis); amount(cap)
        if genesis > cap:
            raise ModelError("genesis exceeds cap")
        self.genesis, self.cap = genesis, cap
        self.minted = self.burned = 0
        self.q = self.p = self.s = self.commission = self.fees = 0
        self.g = {"genesis": genesis}
        self.pending: dict[str, int] = {}
        self.positions: dict[str, int] = {}
        self.cohorts: dict[int, Cohort] = {}
        self.tickets: dict[str, Ticket] = {}
        self.tombstoned = False
        self.seen_evidence: set[str] = set()
        self.check()

    @property
    def total(self) -> int:
        return self.genesis + self.minted - self.burned

    def snapshot(self) -> dict[str, int]:
        return {"total": self.total, "shielded": self.q, "stake": self.p,
                "pending": sum(self.pending.values()),
                "exits": sum(c.assets for c in self.cohorts.values()),
                "commission": self.commission, "fees": self.fees,
                "unclaimed_genesis": sum(self.g.values()),
                "minted": self.minted, "burned": self.burned,
                "stake_shares": self.s}

    def check(self) -> None:
        snapshot = self.snapshot()
        for x in snapshot.values(): amount(x)
        if self.total > self.cap:
            raise AssertionError("technical supply cap exceeded")
        if self.total != sum(snapshot[k] for k in
            ["shielded", "stake", "pending", "exits", "commission", "fees", "unclaimed_genesis"]):
            raise AssertionError("global supply invariant failed")
        if self.s != sum(self.positions.values()):
            raise AssertionError("position shares invariant failed")
        if self.s == 0 and self.p != 0:
            raise AssertionError("unowned pool assets")
        for n, cohort in self.cohorts.items():
            amount(cohort.assets); amount(cohort.shares)
            live = sum(t.units for t in self.tickets.values() if t.cohort == n and not t.claimed)
            if live != cohort.shares:
                raise AssertionError("exit ticket shares invariant failed")
            if cohort.shares == 0 and cohort.assets != 0:
                raise AssertionError("unowned exit assets")

    @atomic
    def claim_genesis(self, claim_id: str = "genesis", fee: int = 0) -> int:
        amount(fee)
        if claim_id not in self.g:
            raise ModelError("genesis already claimed or unknown")
        value = self.g[claim_id]
        if value < fee: raise ModelError("fee exceeds release")
        del self.g[claim_id]
        self.q += value - fee; self.fees += fee
        return value - fee

    @atomic
    def pay_fee(self, fee: int) -> None:
        amount(fee)
        if self.q < fee: raise ModelError("insufficient private funds")
        self.q -= fee; self.fees += fee

    @atomic
    def delegate(self, position: str, value: int, fee: int = 0) -> None:
        amount(value); amount(fee)
        if self.tombstoned: raise ModelError("validator tombstoned")
        if value == 0 or position in self.positions or position in self.pending:
            raise ModelError("invalid or repeated position")
        if self.q < value + fee: raise ModelError("insufficient private funds")
        self.q -= value + fee; self.fees += fee; self.pending[position] = value

    @atomic
    def activate(self, position: str, min_shares: int = 0) -> int:
        amount(min_shares)
        if self.tombstoned: raise ModelError("validator tombstoned")
        if position not in self.pending: raise ModelError("unknown pending")
        value = self.pending[position]
        units = share_quote(self.p, self.s, value)
        if units < min_shares: raise ModelError("slippage")
        del self.pending[position]
        self.p += value; self.s += units; self.positions[position] = units
        return units

    @atomic
    def cancel_pending(self, position: str, fee: int = 0, released: bool = True) -> int:
        amount(fee)
        if position not in self.pending: raise ModelError("unknown pending")
        value = self.pending[position]
        if (released and value < fee) or (not released and self.q < fee):
            raise ModelError("insufficient fee")
        del self.pending[position]
        self.q += value - fee; self.fees += fee
        return value - fee if released else value

    @atomic
    def reward(self, scheduled: int, commission_bps: int = 500,
               eligible: bool = True) -> int:
        amount(scheduled); ratio(0, commission_bps)
        if commission_bps > 2000: raise ModelError("commission exceeds cap")
        if not eligible or self.tombstoned or self.p == 0 or self.s == 0:
            return 0
        minted = min(scheduled, self.cap - self.total)
        gross = minted + self.fees
        c = ratio(gross, commission_bps)
        self.fees = 0; self.minted += minted
        self.p += gross - c; self.commission += c
        return minted

    @atomic
    def unbond(self, position: str, units: int, ticket_id: str, cohort_id: int,
               exposure_height: int, exposure_time: int, fee: int = 0,
               released: bool = True) -> int:
        amount(units); amount(fee)
        if position not in self.positions or units > self.positions[position]:
            raise ModelError("unknown position or insufficient shares")
        if ticket_id in self.tickets: raise ModelError("duplicate ticket")
        gross = redeem_quote(self.p, self.s, units)
        if gross == 0: raise ModelError("zero-value insolvent position")
        if released:
            if gross <= fee: raise ModelError("exit value must exceed fee")
            deposit = gross - fee
        else:
            if self.q < fee: raise ModelError("insufficient fee")
            deposit = gross
            self.q -= fee
        cohort = self.cohorts.setdefault(cohort_id, Cohort(
            exposure_end_height=exposure_height, exposure_end_time=exposure_time))
        if cohort.matured or (cohort.exposure_end_height, cohort.exposure_end_time) != (exposure_height, exposure_time):
            raise ModelError("cohort mismatch")
        exit_units = share_quote(cohort.assets, cohort.shares, deposit)
        self.p -= gross; self.s -= units; self.positions[position] -= units
        self.fees += fee
        cohort.assets += deposit; cohort.shares += exit_units
        self.tickets[ticket_id] = Ticket(position, cohort_id, exit_units)
        return gross

    @atomic
    def slash(self, evidence_id: str, infraction_height: int, bps: int = 500) -> int:
        ratio(0, bps)
        if evidence_id in self.seen_evidence or self.tombstoned:
            return 0
        self.seen_evidence.add(evidence_id); self.tombstoned = True
        burned = ratio(self.p, bps); self.p -= burned
        for cohort in self.cohorts.values():
            if not cohort.matured and cohort.exposure_end_height >= infraction_height:
                loss = ratio(cohort.assets, bps)
                cohort.assets -= loss; burned += loss
        self.burned += burned
        return burned

    @atomic
    def claim_exit(self, ticket_id: str, height: int, chain_time: int,
                   fee: int = 0, released: bool = True,
                   wait_blocks: int = 241_920, wait_seconds: int = 1_209_600,
                   slash_pending: bool = False) -> int:
        amount(fee)
        if ticket_id not in self.tickets: raise ModelError("unknown ticket")
        t = self.tickets[ticket_id]
        if t.claimed: raise ModelError("already claimed")
        c = self.cohorts[t.cohort]
        if (height <= c.exposure_end_height + wait_blocks or
            chain_time <= c.exposure_end_time + wait_seconds or slash_pending):
            raise ModelError("immature or slash pending")
        value = redeem_quote(c.assets, c.shares, t.units)
        if (released and value < fee) or (not released and self.q < fee):
            raise ModelError("insufficient fee")
        c.matured = True; c.assets -= value; c.shares -= t.units
        t.claimed = True; self.q += value - fee; self.fees += fee
        return value - fee if released else value

    @atomic
    def claim_commission(self, value: int, fee: int = 0, released: bool = True) -> int:
        amount(value); amount(fee)
        if value == 0 or value > self.commission: raise ModelError("commission unavailable")
        if (released and value < fee) or (not released and self.q < fee):
            raise ModelError("insufficient fee")
        self.commission -= value; self.q += value - fee; self.fees += fee
        return value - fee if released else value
