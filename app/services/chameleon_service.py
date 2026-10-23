"""
Chameleon Service for VaultPay.

Handles business and cryptographic simulation logic for Chameleon Cards:
1. Card Provisioning: Creates single-use burner cards with integer paise spend limits.
2. Legitimate Purchase & Morphing: Atomically debits user wallet, zeroes the card spend limit,
   and morphs the card into an ARMED_CANARY honeypot.
3. Adversary Probe Detection: Intercepts unauthorized botnet/card-testing probes,
   tarpits the adversary with deceptive responses, logs forensic telemetry, and
   places user account in protective quarantine.
4. Threat Neutralization: Purges the breached token, resolves forensic incidents,
   and restores user account security status.
"""

from datetime import datetime, timezone
import json
import secrets
from typing import Dict, Any, Optional, List

from app.extensions import db
from app.models.chameleon_card import ChameleonCard, CanaryIncident
from app.models.user import User
from app.models.wallet import Wallet
from app.models.transaction import Transaction
from app.utils.money_integer_cents import format_cents, parse_amount_to_cents


def get_user_chameleon_cards(user_id: int) -> List[ChameleonCard]:
    """Returns all Chameleon Cards belonging to the specified user."""
    return ChameleonCard.query.filter_by(user_id=user_id).order_by(ChameleonCard.created_at.desc()).all()


def get_chameleon_card_by_id(card_id: int, user_id: int) -> Optional[ChameleonCard]:
    """Retrieves a specific Chameleon Card ensuring IDOR boundary protection."""
    return ChameleonCard.query.filter_by(id=card_id, user_id=user_id).first()


def create_chameleon_card(
    user_id: int,
    card_name: str,
    merchant_tag: str,
    spend_limit_cents: int
) -> ChameleonCard:
    """
    Provisions a new Chameleon Card in the ACTIVE_BURNER state.
    
    Args:
        user_id: The owner user ID.
        card_name: User-friendly label (e.g., 'AudioGearShop Order #104').
        merchant_tag: Merchant domain (e.g., 'AudioGearShop.in').
        spend_limit_cents: Maximum spending limit in integer paise.
    """
    if spend_limit_cents <= 0:
        raise ValueError("Spending limit must be greater than zero.")

    user = db.session.get(User, user_id)
    if not user:
        raise ValueError("User not found.")

    token_id = f"chm_tok_{secrets.token_hex(16)}"
    masked_pan = ChameleonCard.generate_simulated_pan()

    card = ChameleonCard(
        user_id=user_id,
        card_name=card_name.strip(),
        merchant_tag=merchant_tag.strip(),
        card_token=token_id,
        masked_pan=masked_pan,
        expiry_month=9,
        expiry_year=2029,
        initial_spend_limit_cents=spend_limit_cents,
        spent_amount_cents=0,
        remaining_balance_cents=spend_limit_cents,
        state="ACTIVE_BURNER",
        is_canary=False,
    )

    db.session.add(card)
    db.session.commit()
    return card


def simulate_legitimate_purchase(
    card_id: int,
    user_id: int,
    amount_cents: Optional[int] = None
) -> Dict[str, Any]:
    """
    Simulates the initial legitimate e-commerce purchase.
    
    1. Debits the user's integer wallet balance atomically.
    2. Zeroes out the card's remaining spending limit.
    3. THE MORPH: Transitions the card from ACTIVE_BURNER to ARMED_CANARY.
    """
    card = get_chameleon_card_by_id(card_id, user_id)
    if not card:
        raise ValueError("Chameleon Card not found or unauthorized.")

    if card.state != "ACTIVE_BURNER":
        raise ValueError(f"Card cannot make purchases in state: {card.state}")

    charge_amount = amount_cents if amount_cents is not None else card.initial_spend_limit_cents
    if charge_amount <= 0:
        raise ValueError("Charge amount must be positive.")

    if charge_amount > card.remaining_balance_cents:
        raise ValueError(
            f"Charge amount ({format_cents(charge_amount)}) exceeds card spend limit ({format_cents(card.remaining_balance_cents)})."
        )

    # Check user wallet balance
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if not wallet or wallet.balance_cents < charge_amount:
        raise ValueError(
            f"Insufficient wallet balance ({wallet.formatted_balance if wallet else '₹0.00'}) to authorize {format_cents(charge_amount)}."
        )

    # Atomic financial debit
    wallet.balance_cents -= charge_amount

    # Create immutable audit ledger transaction
    tx = Transaction(
        wallet_id=wallet.id,
        transaction_type="WITHDRAWAL",
        amount_cents=charge_amount,
        status="COMPLETED",
        description=f"Chameleon Card Order: {card.merchant_tag} ({card.masked_pan[-4:]})",
    )
    db.session.add(tx)

    # Morph card into Canary Tripwire
    card.spent_amount_cents += charge_amount
    card.remaining_balance_cents = 0
    card.state = "ARMED_CANARY"
    card.is_canary = True
    card.morphed_at = datetime.now(timezone.utc)

    db.session.commit()

    return {
        "status": "SUCCESS",
        "message": f"Successfully authorized {format_cents(charge_amount)} to {card.merchant_tag}. Card has morphed to ARMED_CANARY.",
        "card": card.to_dict(),
        "wallet_balance": wallet.formatted_balance,
        "transaction_id": tx.id,
    }


def simulate_adversary_probe(
    card_id: int,
    user_id: int,
    attacker_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    probe_amount_cents: int = 100
) -> Dict[str, Any]:
    """
    Simulates an adversary probing or card-checking a leaked card number.
    
    1. Intercepts the unauthorized probe on the ARMED_CANARY card.
    2. Deceptively tarpits the adversary (fake 200/decline response + artificial delay).
    3. Records forensic telemetry (IP, Country, User-Agent, Headers).
    4. Trips the alarm: card state -> TRIPPED.
    5. Places the user account in QUARANTINED status to protect real assets.
    """
    card = get_chameleon_card_by_id(card_id, user_id)
    if not card:
        raise ValueError("Chameleon Card not found or unauthorized.")

    if card.state != "ARMED_CANARY":
        raise ValueError(
            f"Adversary probe requires card to be in ARMED_CANARY state (Current state: {card.state})."
        )

    ip = attacker_ip or "185.220.101.5"
    geo = "Frankfurt, Germany (Tor Exit Relay)" if "185.220" in ip else "Sofia, Bulgaria (Bulletproof Hosting)"
    ua = user_agent or "python-requests/2.31.0 - Automated Card-Testing Botnet"
    merchant = "DarkWeb Bulk-Card-Check Gateway"

    incident_token = f"inc_cnry_{secrets.token_hex(16)}"
    headers = {
        "Host": "api.vaultpay.internal",
        "User-Agent": ua,
        "X-Forwarded-For": ip,
        "CF-Ray": f"{secrets.token_hex(8)}-FRA",
        "Accept": "*/*",
        "Connection": "close",
        "Sec-Ch-Ua": '"Not A(Brand";v="99", "Chromium";v="124"',
        "JA3-Fingerprint": "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16,29-23-24,0",
    }

    # Record forensic incident
    incident = CanaryIncident(
        card_id=card.id,
        user_id=user_id,
        incident_token=incident_token,
        attacker_ip=ip,
        attacker_geo=geo,
        user_agent=ua,
        attempted_merchant=merchant,
        attempted_charge_cents=probe_amount_cents,
        tarpit_delay_ms=1200,
        response_code="DECLINED_INSUFFICIENT_FUNDS",
        headers_dump=json.dumps(headers, indent=2),
    )
    db.session.add(incident)

    # Trip the card
    card.state = "TRIPPED"
    card.tripped_at = datetime.now(timezone.utc)

    # Protective quarantine on user account
    user = db.session.get(User, user_id)
    if user:
        user.security_status = "QUARANTINED"

    db.session.commit()

    return {
        "status": "TRIPWIRE_TRIGGERED",
        "message": f"🚨 Canary tripwire triggered! Card {card.masked_pan} probed by adversary from {ip}.",
        "incident": incident.to_dict(),
        "card": card.to_dict(),
        "user_security_status": "QUARANTINED",
        "tarpit_response": {
            "http_status": 200,
            "simulated_delay_ms": 1200,
            "payload": {
                "status": "declined",
                "code": "insufficient_funds",
                "message": "Card has insufficient balance for authorization.",
            },
        },
    }


def resolve_canary_incident(card_id: int, user_id: int) -> Dict[str, Any]:
    """
    Neutralizes the tripped card, marks incidents as resolved, and restores
    the user account to NORMAL status if no other active tripped cards exist.
    """
    card = get_chameleon_card_by_id(card_id, user_id)
    if not card:
        raise ValueError("Chameleon Card not found or unauthorized.")

    card.state = "NEUTRALIZED"
    card.neutralized_at = datetime.now(timezone.utc)

    # Resolve all associated incidents
    incidents = CanaryIncident.query.filter_by(card_id=card.id, user_id=user_id, resolved=False).all()
    for inc in incidents:
        inc.resolved = True
        inc.resolved_at = datetime.now(timezone.utc)

    # Check if user has any other TRIPPED cards
    other_tripped = ChameleonCard.query.filter(
        ChameleonCard.user_id == user_id,
        ChameleonCard.id != card.id,
        ChameleonCard.state == "TRIPPED"
    ).count()

    user = db.session.get(User, user_id)
    if user and other_tripped == 0:
        user.security_status = "NORMAL"

    db.session.commit()

    return {
        "status": "RESOLVED",
        "message": f"Card {card.masked_pan} neutralized and purged. Account status restored to NORMAL.",
        "card": card.to_dict(),
        "user_security_status": user.security_status if user else "NORMAL",
        "resolved_incidents_count": len(incidents),
    }


def reset_or_create_demo_chameleon(user_id: int) -> ChameleonCard:
    """
    Provisions a fresh demo Chameleon Card for the user's simulation session,
    clearing previous demo state so the user can rerun the full simulation smoothly.
    """
    user = db.session.get(User, user_id)
    if user:
        user.security_status = "NORMAL"

    # Reset any existing cards in simulation
    existing = ChameleonCard.query.filter_by(user_id=user_id, merchant_tag="AudioGearShop.in").first()
    if existing:
        db.session.delete(existing)
        db.session.commit()

    # Ensure user has sufficient funds in wallet for the demo (minimum ₹2,000)
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if wallet and wallet.balance_cents < 200000:
        wallet.balance_cents = 250000  # ₹2,500.00
        db.session.commit()

    return create_chameleon_card(
        user_id=user_id,
        card_name="AudioGear Order #104",
        merchant_tag="AudioGearShop.in",
        spend_limit_cents=149900  # ₹1,499.00
    )
