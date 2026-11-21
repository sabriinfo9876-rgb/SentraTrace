from dataclasses import dataclass

LOGIN_LIMIT = 5
LOGIN_WINDOW = 60
NETWORK_LOGIN_LIMIT = 30


@dataclass(frozen=True)
class Decision:
    type: str
    status: str
    risk: int
    reason: str
    recommendation: str


def check_ownership(requester: str, owner: str | None) -> Decision:
    if requester == owner:
        return Decision("Account access", "Allowed", 0, "Account ownership verified.", "")
    return Decision(
        "Account access denied", "Blocked", 90,
        "The requested account was unavailable to this identity.",
        "Check object ownership against the authenticated identity on each request.",
    )


def limit_reached(attempts: int, limit: int = LOGIN_LIMIT) -> bool:
    return attempts >= limit


def preview_decision(kind: str) -> tuple[str, Decision]:
    if kind == "bola":
        return "/api/accounts/{account_id}", check_ownership("fixture-viewer", "fixture-owner")
    status = "Blocked" if limit_reached(LOGIN_LIMIT) else "Allowed"
    return "/api/auth/login", Decision(
        "Login rate limit", status, 85 if status == "Blocked" else 0,
        f"The preset login counter has reached {LOGIN_LIMIT} attempts in {LOGIN_WINDOW} seconds.",
        "Throttle sign-in attempts before checking credentials.",
    )
