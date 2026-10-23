# Latch admin: decisions made during implementation

This document goes with `2026-10-23-latch-admin.md`. It lists the calls made while the plan was being carried out, wherever the plan said nothing, was unclear, or was wrong. For each call it says:

- what was decided;
- why;
- what it costs if the decision turns out wrong.

The spec is still the binding authority.

## Changes to what the plan said

- **Self-lockout through groups.** An admin can't remove admin access from their own only admin group, or delete it, even when another admin group exists. Unticking your own admin group already got this refusal, and the same lockout follows here. The other admin group might have no members. Cost if wrong: an admin has to ask another admin to make the change.
- **Your own member page.** It leaves out "Set password manually" as well as disable and delete. Using it would sign the admin out of the session they're using. The page already sends them to their account page instead.
- **Deleting a group.**
  - The admin pages and the API both refuse to delete a group when it is the only group allowed into some app. The refusal names each such app.
  - Without this, the database removes the app's group list and the app then opens to every active member. The old confirmation text promised the opposite.
  - A store-level guard closes the race between the check and the delete.
- **Two-step sign in on the admin pages is checked on every request.** If you aren't enrolled and any of your groups requires two-step sign in, the admin pages send you to set it up first.
  - Before this, a member promoted into the Admin group kept using a password-only session that started earlier. The same happened when an admin group was switched to require two-step.
  - Member pages keep the spec's rule: enrolment happens at next sign-in.
- **Failed invitation emails.** When an invitation or reset email can't be sent, the link that was just made is deleted. The member stays "Needs password" instead of showing "Invited, not set up" for an email that never went out. The admin's attempt is still recorded, with `email_sent: false`.
- **Invitation or password, not both.** Asking for an invitation and also setting a password is refused with a field message, rather than dropping the password silently.
- **Home page tiles need a link.** An app shown on the home page must have a link to open it. Otherwise the tile was hidden with no explanation.
- **Lists in the API.** Every list in the API pages the same way, including `/groups`, `/apps` and the token list, which the plan called unpaginated. The page number is capped at 1,000,000, so a huge `?page=` gives an empty page instead of a server error.
- **`null` in an app PATCH.** In an app PATCH, a field that is left out stays as it is. `null` resets a lifetime to the global default and turns machine-to-machine sign-in off. This matches the plan's "null means the default" rule. The member PATCH keeps its own rule: `null` leaves a field alone.
- **`service_account_id` on apps.** It is `null` in the API when the app has no service account, not an empty string.

## Security and audit calls beyond the plan

- **Privilege grants in the audit log.**
  - Creating a member or a service account straight into groups records a `group.member.add` event for each group.
  - Summaries name the privilege change, for example:
    - "Gave group Laser admin access";
    - turning two-step on or off;
    - "Made full admin API token …" versus "Made read-only API token …".
  - Deleted targets show the name kept in the event's detail.
- **Icon files live in `internal/icons`.** This package covers saving, checking, ownership and removal, so the pages and the API share it. The API deletes an app's icon file when the app is deleted or its icon changes. A test puts real files beside the icon folder to prove `/icons/` can't serve anything outside it.
- **Email failures in the API** are logged with the address redacted. The admin service never logs the SMTP error.
- **Add and save forms say when nothing was saved.** A rejected form now shows a line at the top of the page as well as the field messages. A failed action, such as a short password or a mistyped delete confirmation, shows a one-line summary at the top too.

## Smaller accepted choices

- Over-long names and usernames get "Use at most N characters."
- One duration formatter, `admin.FormatDuration`, serves both the app form and the refresh-lifetime message.
- The shown-once secret page labels its MediaWiki snippet, and the token page labels its curl example.
- Commits made by subagents carry their own model's attribution line.

## Accepted as is, deliberately

- **Every human admin can be removed by an API token.** An admin-scope API token can disable or delete every human admin. The break-glass is `latch create-admin`.
- **Resubmitting a secret page.** The shown-once secret pages answer a POST directly. Back plus resubmit would rotate a secret again or make a second token. Browsers ask before resubmitting, and the pages are `no-store`.
- **Access tokens outlive a disabled account** until they expire. This is the core design from spec §6.1.
- **No CORS headers on the admin API**, which is for scripts and devices.
- **No rate limit before authentication.** API tokens are 256-bit.
- **No service-account email field**, because the §7 form omits one.
- **Browser apps and the CORS cache.** A newly registered browser app can fail CORS for up to a minute, until the cache of allowed origins refreshes.
- **Usernames are unique only by exact case.** Fixing this needs a migration. Revisit it with the importer.
- **Some small helpers are duplicated**: the address redaction, the account-name formatting and the MediaWiki snippet.
- **The add-app form ticks "Show on members' home page" by default.** An app with no link needs that box unticked on first save, and the message says so.
- **A form post that has to go through two-step setup** lands on a "method not allowed" page afterwards. The member pages already behave the same way.

## Carry into the importer plan

- Imported apps must pass the same checks as hand-made ones, because every save re-checks the whole app. That means:
  - icon addresses are https or `/icons/` (Authentik's relative `/media/...` paths won't pass);
  - at most 20 return addresses;
  - lifetimes within the caps;
  - the home page tile only with a link.
- Store an empty legacy hash for Authentik's unusable `!…` hashes, so those members show "Needs password".
- Add the import status section to the Settings page.
- Decide whether usernames should become unique regardless of case before importing.
- Document backing up `data_dir/icons` alongside the database.

## Not done here, deliberately

- `/metrics`, the Dockerfile, the systemd unit and the cutover runbook belong to the importer plan.
- **Small follow-ups the reviews raised and left.** None of them blocks use:
  - test gaps;
  - wording polish;
  - a few long parameter lists;
  - wall-clock `ago`;
  - the 404 page without the sidebar;
  - clear links on the audit page dropping other filters.
