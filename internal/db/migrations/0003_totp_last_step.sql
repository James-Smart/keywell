-- The time step (Unix time / 30) of the last TOTP code accepted for this
-- user, so that no code is accepted twice (RFC 6238 §5.2). NULL when none
-- has been, or since TOTP was turned off.
ALTER TABLE users ADD COLUMN totp_last_step INTEGER;
