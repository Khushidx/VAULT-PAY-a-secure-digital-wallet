"""
Chameleon Simulator Blueprint.

Routes and endpoints for the interactive Chameleon Card & Canary Tripwire Lab:
- GET  /chameleon-simulator                 -> Renders the 4-stage interactive simulation laboratory
- POST /chameleon-simulator/api/create-card -> Provisions a new Chameleon Card
- POST /chameleon-simulator/api/purchase    -> Simulates legitimate purchase & card morphing
- POST /chameleon-simulator/api/probe       -> Simulates adversary botnet probe on leaked card
- POST /chameleon-simulator/api/resolve     -> Resolves incident, neutralizes card, restores vault
- POST /chameleon-simulator/api/reset       -> Resets demo scenario to initial state
"""

from flask import Blueprint, render_template, request, jsonify, g, flash, redirect, url_for
from app.utils.decorators import login_required
from app.utils.money_integer_cents import parse_amount_to_cents, format_cents
from app.models.chameleon_card import ChameleonCard, CanaryIncident
from app.services.chameleon_service import (
    get_user_chameleon_cards,
    get_chameleon_card_by_id,
    create_chameleon_card,
    simulate_legitimate_purchase,
    simulate_adversary_probe,
    resolve_canary_incident,
    reset_or_create_demo_chameleon,
)

chameleon_lab_bp = Blueprint("chameleon_lab", __name__, url_prefix="/chameleon-simulator")


@chameleon_lab_bp.route("", methods=["GET"])
@chameleon_lab_bp.route("/", methods=["GET"])
@login_required
def index():
    """
    Renders the interactive Chameleon Card & Canary Tripwire Simulator.
    Supports querying a specific card via ?card_id=<id>.
    """
    cards = get_user_chameleon_cards(g.current_user.id)
    requested_card_id = request.args.get("card_id", type=int)

    active_card = None
    if requested_card_id and cards:
        active_card = next((c for c in cards if c.id == requested_card_id), None)

    if not active_card:
        active_card = cards[0] if cards else reset_or_create_demo_chameleon(g.current_user.id)
        if not cards:
            cards = [active_card]

    # Fetch latest incident for active_card or latest user incident
    latest_incident = CanaryIncident.query.filter_by(
        card_id=active_card.id, user_id=g.current_user.id
    ).order_by(CanaryIncident.created_at.desc()).first()
    if not latest_incident:
        latest_incident = CanaryIncident.query.filter_by(
            user_id=g.current_user.id
        ).order_by(CanaryIncident.created_at.desc()).first()

    return render_template(
        "chameleon_lab/index.html",
        card=active_card.to_dict(),
        cards=[c.to_dict() for c in cards],
        incident=latest_incident.to_dict() if latest_incident else None,
        user_status=g.current_user.security_status,
        wallet_balance=g.current_user.wallet.formatted_balance if g.current_user.wallet else "₹0.00",
    )


@chameleon_lab_bp.route("/api/cards/<int:card_id>", methods=["GET"])
@login_required
def api_get_card(card_id: int):
    """Fetches details and latest incident for a specific Chameleon Card."""
    card = get_chameleon_card_by_id(card_id, g.current_user.id)
    if not card:
        return jsonify({"success": False, "error": "Chameleon Card not found."}), 404

    latest_incident = CanaryIncident.query.filter_by(
        card_id=card.id, user_id=g.current_user.id
    ).order_by(CanaryIncident.created_at.desc()).first()

    return jsonify({
        "success": True,
        "card": card.to_dict(),
        "incident": latest_incident.to_dict() if latest_incident else None,
    })


@chameleon_lab_bp.route("/api/create-card", methods=["POST"])
@login_required
def api_create_card():
    """Provisions a new Chameleon Card."""
    data = request.get_json(silent=True) or request.form or {}
    card_name = str(data.get("card_name", "Decoy Card")).strip() or "Decoy Card"
    merchant_tag = str(data.get("merchant_tag", "OnlineStore.in")).strip() or "OnlineStore.in"
    amount_str = str(data.get("spend_limit", "1499.00")).strip() or "1499.00"

    try:
        is_valid, spend_limit_cents, err_msg = parse_amount_to_cents(amount_str)
        if not is_valid or spend_limit_cents <= 0:
            return jsonify({"success": False, "error": err_msg or "Spend limit must be greater than zero."}), 400

        card = create_chameleon_card(
            user_id=g.current_user.id,
            card_name=card_name,
            merchant_tag=merchant_tag,
            spend_limit_cents=spend_limit_cents,
        )
        return jsonify({
            "success": True,
            "message": f"Chameleon Card '{card.card_name}' created with limit {format_cents(spend_limit_cents)}.",
            "card": card.to_dict(),
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400


@chameleon_lab_bp.route("/api/purchase", methods=["POST"])
@login_required
def api_purchase():
    """
    Simulates the legitimate purchase and triggers the morph to ARMED_CANARY.
    """
    data = request.get_json(silent=True) or request.form or {}
    card_id = data.get("card_id")
    if not card_id:
        cards = get_user_chameleon_cards(g.current_user.id)
        if not cards:
            return jsonify({"success": False, "error": "No card found."}), 404
        card_id = cards[0].id

    try:
        result = simulate_legitimate_purchase(card_id=int(card_id), user_id=g.current_user.id)
        return jsonify({
            "success": True,
            **result
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400


@chameleon_lab_bp.route("/api/probe", methods=["POST"])
@login_required
def api_probe():
    """
    Simulates an adversary probe on the morphed canary card.
    """
    data = request.get_json(silent=True) or request.form or {}
    card_id = data.get("card_id")
    if not card_id:
        cards = get_user_chameleon_cards(g.current_user.id)
        if not cards:
            return jsonify({"success": False, "error": "No card found."}), 404
        card_id = cards[0].id

    attacker_ip = data.get("attacker_ip")
    user_agent = data.get("user_agent")
    probe_amount = int(data.get("probe_amount_cents", 100))

    try:
        result = simulate_adversary_probe(
            card_id=int(card_id),
            user_id=g.current_user.id,
            attacker_ip=attacker_ip,
            user_agent=user_agent,
            probe_amount_cents=probe_amount,
        )
        return jsonify({
            "success": True,
            **result
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400


@chameleon_lab_bp.route("/api/resolve", methods=["POST"])
@login_required
def api_resolve():
    """
    Resolves the incident, neutralizes the card, and restores user account status.
    """
    data = request.get_json(silent=True) or request.form or {}
    card_id = data.get("card_id")
    if not card_id:
        cards = get_user_chameleon_cards(g.current_user.id)
        if not cards:
            return jsonify({"success": False, "error": "No card found."}), 404
        card_id = cards[0].id

    try:
        result = resolve_canary_incident(card_id=int(card_id), user_id=g.current_user.id)
        return jsonify({
            "success": True,
            **result
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400


@chameleon_lab_bp.route("/api/reset", methods=["POST"])
@login_required
def api_reset():
    """
    Resets the demo scenario to initial state with a fresh Chameleon Card.
    """
    try:
        card = reset_or_create_demo_chameleon(g.current_user.id)
        return jsonify({
            "success": True,
            "message": "Demo scenario reset successfully.",
            "card": card.to_dict(),
            "user_security_status": g.current_user.security_status,
            "wallet_balance": g.current_user.wallet.formatted_balance if g.current_user.wallet else "₹0.00",
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
