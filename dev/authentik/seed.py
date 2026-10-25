# Seeds the Authentik dev stack with the importer's test fixture.
# Run by up.sh through `ak shell`. Uses natural keys, so it is safe to run twice.
from datetime import datetime, timezone

from django.contrib.auth.hashers import check_password, make_password

from authentik.core.models import Application, Group, User, UserTypes
from authentik.flows.models import Flow
from authentik.policies.expression.models import ExpressionPolicy
from authentik.policies.models import PolicyBinding
from authentik.providers.oauth2.models import (
    OAuth2Provider,
    RedirectURI,
    RedirectURIMatchingMode,
    RedirectURIType,
    ScopeMapping,
)
from authentik.providers.saml.models import SAMLProvider
from authentik.stages.authenticator_static.models import StaticDevice, StaticToken
from authentik.stages.authenticator_totp.models import TOTPDevice

created = {}


def note(kind, was_created):
    created.setdefault(kind, [0, 0])[0 if was_created else 1] += 1


def upsert(model, kind, lookup, defaults):
    obj, was_created = model.objects.update_or_create(**lookup, defaults=defaults)
    note(kind, was_created)
    return obj


authz_flow = Flow.objects.get(slug="default-provider-authorization-implicit-consent")
invalidation_flow = Flow.objects.get(slug="default-provider-invalidation-flow")

# Groups
members = upsert(
    Group, "groups", {"name": "Members"},
    {"attributes": {"door": "yes", "goauthentik.io/internal": True}, "is_superuser": False},
)
laser = upsert(Group, "groups", {"name": "Laser"}, {"attributes": {"induction": "2024"}, "is_superuser": False})
trustees = upsert(Group, "groups", {"name": "Trustees"}, {"attributes": {}, "is_superuser": True})
for child in (laser, trustees):
    child.parents.add(members)

# Users. pw is (password, hasher); hasher None means Django's default.
USERS = [
    ("alex", "Alex.Smith@Example.org", "Alex Smith", "internal", True, ("alex correct horse 1", None), [laser]),
    ("sam", "sam@example.org", "Sam Jones", "internal", True, ("sam correct horse 2", "argon2"), [trustees]),
    ("jo", "jo@example.org", "", "internal", True, "unusable", [members]),
    ("pat", "pat@example.org", "Pat Inactive", "internal", False, ("pat correct horse 3", None), [members]),
    ("kim", "kim@example.org", "Kim External", "external", True, ("kim correct horse 4", "scrypt"), []),
    ("nomail", "", "No Mail", "internal", True, ("nomail correct horse 5", None), [members]),
    ("door-bot", "", "door-bot", "service_account", True, None, []),
]
users = {}
for username, email, name, utype, active, pw, groups in USERS:
    attrs = {"member_number": 42, "goauthentik.io/user/sources": []} if username == "alex" else {}
    user = upsert(
        User, "users", {"username": username},
        {"email": email, "name": name, "type": UserTypes(utype), "is_active": active, "attributes": attrs},
    )
    if pw == "unusable":
        # Django's unusable password has a random suffix; set it only once.
        if not user.password.startswith("!"):
            user.set_unusable_password()
    elif pw is not None:
        # Hash only if the stored hash is not already this password under this
        # hasher; make_password salts randomly, so rehashing would change rows.
        text, hasher = pw
        want = hasher or "pbkdf2_sha256"
        if not (user.password.startswith(want + "$") and check_password(text, user.password, setter=None)):
            user.password = make_password(text, hasher=hasher or "default")
    user.save()
    user.groups.set(groups)
    users[username] = user

admin = User.objects.get(username="akadmin")
admin.email = "akadmin@example.org"
admin.save()
admin.groups.add(Group.objects.get(name="authentik Admins"))


def utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


# Two-step
alex, pat = users["alex"], users["pat"]
for name, key, confirmed, last_used, last_t in [
    ("Old phone", "3132333435363738393031323334353637383931", True, utc(2025, 1, 1), 0),
    ("Phone", "3132333435363738393031323334353637383930", True, utc(2026, 10, 1), 1000),
    ("Tablet", "3132333435363738393031323334353637383932", False, None, 0),
]:
    upsert(
        TOTPDevice, "totp devices", {"user": alex, "name": name},
        {"key": key, "confirmed": confirmed, "last_used": last_used, "last_t": last_t,
         "step": 30, "t0": 0, "digits": 6},
    )
upsert(
    TOTPDevice, "totp devices", {"user": pat, "name": "Pat phone"},
    {"key": "3132333435363738393031323334353637383933", "confirmed": True, "step": 30, "t0": 0, "digits": 8},
)
static = upsert(StaticDevice, "static devices", {"user": alex, "name": "Recovery codes"}, {"confirmed": True})
for token in ("RecoveryAAA1", "RecoveryBBB2", "RecoveryCCC3"):
    _, was_created = StaticToken.objects.get_or_create(device=static, token=token)
    note("static tokens", was_created)

# Claim mappings
builtin = list(
    ScopeMapping.objects.filter(
        managed__in=[
            "goauthentik.io/providers/oauth2/scope-openid",
            "goauthentik.io/providers/oauth2/scope-email",
            "goauthentik.io/providers/oauth2/scope-profile",
        ]
    )
)
assert len(builtin) == 3, builtin
wiki_extra = upsert(
    ScopeMapping, "claim mappings", {"name": "Wiki extra claims"},
    {"scope_name": "wiki", "expression": 'return {"wiki": True}'},
)

S, R = RedirectURIMatchingMode.STRICT, RedirectURIMatchingMode.REGEX
AUTH, LOGOUT = RedirectURIType.AUTHORIZATION, RedirectURIType.LOGOUT


def oauth(name, client_id, client_type, secret, sub_mode, access, refresh, uris, mappings, grant_types=None):
    defaults = {
        "client_id": client_id, "client_type": client_type, "client_secret": secret,
        "sub_mode": sub_mode, "access_token_validity": access, "refresh_token_validity": refresh,
        "authorization_flow": authz_flow, "invalidation_flow": invalidation_flow,
        "redirect_uris": uris,
    }
    if grant_types is not None:
        defaults["grant_types"] = grant_types
    prov = upsert(OAuth2Provider, "oauth2 providers", {"name": name}, defaults)
    prov.property_mappings.set(mappings)
    return prov


wiki_p = oauth(
    "wiki", "wiki-client-id", "confidential", "wiki-client-secret-0123456789", "hashed_user_id",
    "hours=2", "days=30",
    [
        RedirectURI(S, "https://wiki.example.org/index.php/Special:PluggableAuthLogin", AUTH),
        RedirectURI(R, r"https://.*\.example\.org/cb", AUTH),
        RedirectURI(S, "https://wiki.example.org/", LOGOUT),
    ],
    builtin + [wiki_extra],
)
door_p = oauth(
    "door-app", "door-app-client-id", "public", "", "user_email", "minutes=5", "weeks=20",
    [RedirectURI(S, "https://door.example.org/callback", AUTH)], builtin,
)
tools_p = oauth(
    "tools", "tools-client-id", "confidential", "tools-client-secret-0123456789", "user_uuid",
    "hours=36", "days=30",
    [RedirectURI(S, "https://tools.example.org/oauth/callback", AUTH)], builtin,
    grant_types=["authorization_code", "client_credentials"],
)
oauth(
    "orphan", "orphan-client-id", "confidential", "orphan-client-secret-0123456789", "hashed_user_id",
    "hours=1", "days=30", [RedirectURI(S, "https://orphan.example.org/cb", AUTH)], builtin,
)
grafana_p = upsert(
    SAMLProvider, "saml providers", {"name": "grafana-saml"},
    {"acs_url": "https://grafana.example.org/saml/acs",
     "authorization_flow": authz_flow, "invalidation_flow": invalidation_flow},
)

# Applications
APPS = [
    ("Wiki", "wiki", wiki_p, "https://wiki.example.org/", "/media/public/application-icons/wiki.png", "The makerspace wiki"),
    ("Door Booking", "Door_Booking", door_p, "https://door.example.org/", "https://door.example.org/icon.png", ""),
    ("Tool Booking", "tools", tools_p, "https://tools.example.org/", "", ""),
    ("Grafana", "grafana", grafana_p, "", "", ""),
    ("Printer", "printer", None, "", "", ""),
]
apps = {}
for name, slug, prov, launch, icon, desc in APPS:
    apps[slug] = upsert(
        Application, "applications", {"slug": slug},
        {"name": name, "provider": prov, "meta_launch_url": launch, "meta_icon": icon, "meta_description": desc},
    )

# Access rules
weekdays = upsert(
    ExpressionPolicy, "policies", {"name": "Weekdays only"}, {"expression": "return True"},
)
for app, group in ((apps["wiki"], members), (apps["tools"], laser)):
    upsert(PolicyBinding, "bindings", {"target": app, "group": group, "order": 0}, {"enabled": True, "negate": False})
upsert(PolicyBinding, "bindings", {"target": apps["tools"], "policy": weekdays, "order": 1}, {"enabled": True, "negate": False})

for kind, (new, existing) in created.items():
    print(f"{kind}: {new} created, {existing} already there")
