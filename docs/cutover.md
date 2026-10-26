# Moving from Authentik to Keywell

This is a checklist for the person doing the move. You don't need to know how Keywell works inside. You do need to be able to log in to the server that runs Authentik, the server that will run Keywell, and the server that runs the wiki.

The plan: install Keywell beside Authentik, copy everything across a few times to practise, then on one chosen day copy it a last time and point the wiki and the other apps at Keywell. Authentik stays untouched until you are happy, so you can always go back.

Every command below was tried against a test Authentik. Where a command has `…` in it, fill in your own value.

## 1. What changes for members

- The login page looks different. Nothing else does.
- Passwords carry over, so members sign in with the password they have now.
- Authenticator apps carry over too, with their recovery codes. Members keep using the same app and the same codes.
- A few members may have a password Keywell can't check. The report counts them as "no usable password" (see "Reading the report"). They click "Forgot your password?" on the login page and get an email with a link to choose a new one. If email isn't set up, or someone is stuck, run `sudo -u keywell keywell reset-password --config /etc/keywell/keywell.yaml their@email` on the Keywell server and send them the link it prints. Under Docker, run `docker compose -f deploy/docker-compose.yml run --rm keywell reset-password --config /var/lib/keywell/keywell.yaml their@email` instead. (Section 2, step 4 explains the `sudo -u keywell`.)
- The wiki and your own apps see the same member IDs as before, so nobody loses their account in an app.

## 2. A week before

1. **Install Keywell** on its own web address, for example `https://login.example.org`, following "Running Keywell for real" in the README. Authentik keeps running on its own address. Don't send members to Keywell yet.

   `keywell init` ends by telling you to edit `keywell.yaml`. If you run Keywell under Docker, don't: the image has no editor, and you change settings with `KEYWELL_…` variables instead. The Docker part of "Running Keywell for real" in the README explains how.

2. **Take a copy of Authentik's database.** On the server that runs Authentik, go to the folder that holds Authentik's `docker-compose.yml` and run:

   ```sh
   docker compose exec -T postgresql pg_dump -U authentik -d authentik -Fc > authentik.dump
   ```

   This only reads. Authentik carries on as normal. If the database service, user or database has another name on your server, use those names. They are in Authentik's `.env` file and compose file.

   The dump holds more than everyone's password hashes. It also holds every member's two-step sign in keys and recovery codes, and your apps' client secrets, and anyone who gets the file can use those as they are. Keep it private, and delete every copy when you finish (section 7).

   Then copy `authentik.dump` to the Keywell server, for example with `scp authentik.dump you@keywell-server:`, and do step 3 there. If Authentik and Keywell run on the same server, there is nothing to copy.

3. **Put the copy into a throwaway database.** Do this on the Keywell server, in the folder that holds `authentik.dump`. This is a small, temporary database that exists only so Keywell can read the copy. Pick any password for it. You will use the same password again in step 4, so type it once into `PGPASSWORD`. This way it isn't saved in your shell history (in fish, use `read -s -x PGPASSWORD` instead):

   ```sh
   read -rs PGPASSWORD && export PGPASSWORD
   docker run -d --name ak-copy -e POSTGRES_PASSWORD="$PGPASSWORD" -p 127.0.0.1:55433:5432 postgres:16-alpine
   docker exec ak-copy createdb -U postgres authentik
   docker exec -i ak-copy pg_restore -U postgres -d authentik --no-owner < authentik.dump
   ```

   Use the same major version of Postgres as Authentik's own. It is the `image:` line of the `postgresql` service in Authentik's `docker-compose.yml`, which is `postgres:16-alpine` in Authentik 2026.8's standard file. If yours says another number, use that number instead of `16`, or the restore fails.

   Wait a few seconds after the `docker run` line before running the next. The restore prints nothing when it works.

4. **Try the import without saving anything.** This is called a dry run. The password is the one you chose in step 3, in `PGPASSWORD`. Keeping it there rather than in the address means it never shows up in the `--from` address, in Keywell's report or in its error messages. If you are in a new terminal, set it again the same way (`read -rs PGPASSWORD && export PGPASSWORD`). On the Keywell server:

   ```sh
   sudo -u keywell --preserve-env=PGPASSWORD keywell import-authentik --config /etc/keywell/keywell.yaml --dry-run \
     --from postgres://postgres@127.0.0.1:55433/authentik
   ```

   This is for Keywell installed with the systemd steps in the README. There, only the `keywell` user can read Keywell's config file and write its database, so the command runs as that user (`sudo -u keywell`). `sudo` normally drops your environment variables, `PGPASSWORD` among them, and `--preserve-env=PGPASSWORD` passes that one on. Don't run the import as root instead: it can leave files beside the database that belong to root, which Keywell then can't open.

   Never type a password into the `--from` address.

   **If Keywell runs under Docker,** run the command through compose, and hand the password to the container with `-e PGPASSWORD`:

   ```sh
   docker compose -f deploy/docker-compose.yml run --rm -e PGPASSWORD keywell import-authentik \
     --config /var/lib/keywell/keywell.yaml --dry-run \
     --from postgres://postgres@ak-copy:5432/authentik
   ```

   If you need `sudo` to run `docker`, keep the password the same way: `sudo --preserve-env=PGPASSWORD docker compose -f deploy/docker-compose.yml run --rm -e PGPASSWORD keywell import-authentik …`, with the rest as above.

   Inside the container, `127.0.0.1` is the container itself, not your server, so an address that starts `127.0.0.1` fails with "connection refused". The container must reach the throwaway database some other way: by your server's own address, or by sharing a Docker network with it. The simple way is the shared network. Docker Compose names Keywell's network after the folder the compose file is in, plus `_default`, so `deploy_default` for `deploy/docker-compose.yml`. Check with `docker network ls`, then join the throwaway database to it:

   ```sh
   docker network connect deploy_default ak-copy
   ```

   The address then uses the database's container name, `ak-copy`, and its normal port 5432, as above. (The other way is to publish the throwaway database on your server's own address instead of `127.0.0.1` and use that address in `--from`. That makes it reachable from the whole network, so use a strong password and remove it afterwards.)

5. **Read the report** (next section). Fix what you can in Authentik, take a new copy (steps 2 and 3, running `docker rm -f ak-copy` first to start clean), and run the dry run again. Repeat until you're happy. A dry run is safe to repeat as often as you like, and safe while Keywell is running.

**Another way, without a copy.** You can point `--from` at Authentik's own database. The import only reads from it. But Authentik's database isn't reachable from outside its container by default, so you would first have to publish its port (add `ports: ["127.0.0.1:5432:5432"]` to its database service in Authentik's compose file and restart it). Most people find the copy simpler and safer, and it gives you something to practise on.

## 3. Reading the report

The command prints the report. After a real import it is also kept in Keywell, under Settings, then Import from Authentik. Each skipped item and each warning has its own line:

```
member nomail: Has no email address, which Keywell needs to sign them in.
app Wiki: Its icon is stored in Authentik. Upload it on the app's page.
```

*Skipped* means that item is not copied. *Warnings* mean it is copied, with something for you to look at. Below, each message is shown with its fixed words, and `…` stands for the part that changes. Each says whether to fix it in Authentik before the final import, or on the item's page in Keywell afterwards.

### Top of the report

| It says | What it means |
|---|---|
| `Dry run of an import from …. Nothing was saved.` | You ran with `--dry-run`. |
| `Imported from ….` | A real import finished. |
| `Members: … added, … updated, … skipped` (also Groups and Apps) | The totals. "Updated" counts everything that matched something already in Keywell, even if nothing changed. |
| `Left out … service accounts and Authentik's own accounts.` | Nothing to do. These are not people and are not copied. |
| `Two-step sign in carried over for … members, with … recovery codes.` | Nothing to do. |
| `… members already use Keywell and kept their Keywell password and two-step sign in.` | Members who signed in to Keywell after an earlier import. Their Keywell password is never replaced. |
| `… members have no usable password and will need a reset link.` | See "What changes for members". |
| `Metadata apps will see for members:` (and `…for groups:`), then a list of names with counts | See "Extra details apps can see". |

### Extra details apps can see

Authentik lets you store extra details on members and groups. Keywell passes them to apps as "metadata". The report lists each name it found, with how many members or groups have it, for example `member_number (1 member)`. Names that begin with `goauthentik.io/` are Authentik's own and are dropped without being listed. If a name on the list is something you don't want apps to see, leave it out by adding `--drop-key NAME` to the command, once for each name:

```sh
sudo -u keywell --preserve-env=PGPASSWORD keywell import-authentik --config /etc/keywell/keywell.yaml --dry-run \
  --from … --drop-key secret_note --drop-key internal_id
```

Use the same `--drop-key` options on the final import.

### Fix these first

If the report starts like this, nothing was imported, and nothing will be until you fix every line under it:

```
Nothing was imported from …. Fix these first:
  …
```

Find your line below.

- `Authentik members … and … have the same email address apart from capitals. Keywell needs a different email address for each member, so change one of them in Authentik.` Change one of the two email addresses in Authentik.
- `… is linked to …, but … already has that email address. Change the email address of one of them in Authentik or Keywell.` Two people clash. Change one address.
- `… has the email address of …, but that Keywell member is linked to …. Change the email address of one of them in Authentik or Keywell.` Same.
- `… has the username …, which … already has. Change one of the usernames in Authentik or Keywell.` Change one username.
- `Authentik has two groups called …. Rename one of them in Authentik.`
- `Authentik group … has the same name as Keywell group …, which is linked to a different Authentik group. Rename the Keywell group on its page, then import again.` Rename it in Keywell, on the group's page.
- `Authentik group … is linked to Keywell group …, but another Keywell group is already called …. Rename that Keywell group on its page, then import again.` Rename that group in Keywell.
- `Authentik's group "…" has the same name as Keywell's admin group. Rename one of them before importing.` Rename one of the two.
- `Keywell has no admin group, so "…" can't be limited to admins. Give a group admin access before importing.` On a group's page in Keywell, give it admin access.

After fixing, take a fresh copy and run the dry run again.

### Members: skipped

- `Has no email address, which Keywell needs to sign them in.` Add an email address in Authentik if they should be able to sign in. Otherwise leave them out.
- `Has an email address Keywell can't use.` Correct the address in Authentik.

These two are only for members Keywell doesn't have yet. A member an earlier import brought in gets a warning instead (next list).

### Members: warnings

- `Has a password Keywell can't check. They'll need a reset link.` See "What changes for members".
- `Used a kind of two-step code Keywell doesn't support. They'll set up two-step sign in again.` Tell them. They set it up again the next time they sign in.
- `Had … authenticator apps in Authentik. Keywell kept the one used most recently ("…").` Nothing to do. If they say their code doesn't work, this is why.
- `Has a username Keywell can't use, so it was left off.` Optional: fix the username in Authentik.
- `Has a name longer than Keywell allows. Keywell kept it, but shorten it before editing them on their page.` Optional, in Authentik.
- `Has more than 8 KB of metadata. Keywell kept it, but shorten it before editing them on their page.` Optional, in Authentik.
- `Has the username …, which differs only in capitals from the username … of member …. Keywell keeps both, but apps that ignore capitals may mix them up.` Rename one in Authentik if any of your apps ignores capitals.
- `Was linked to an Authentik account that no longer exists. Keywell now links them to this one, so apps that identify people by their Authentik ID will see a new ID.` Their Authentik account was deleted and made again. An app that identifies people by their Authentik ID will treat them as a new person. Check that app for them after the switch.
- `Is no longer in Authentik. Keywell has left them as they are.` See "Things that disappear from Authentik".
- `Has no usable email address in Authentik, so Keywell kept the one it had.` An earlier import brought them in, and since then their email address in Authentik was removed or broken. Everything else about them is still copied from Authentik, so if Authentik turned them off, Keywell does too. Correct the address in Authentik.
- `Is now a service account in Authentik, so Keywell turned their account off.` An earlier import brought them in as a person, and Authentik now marks the account as a service account. Keywell turns them off and signs them out, and changes nothing else. If that was a mistake, change the account back in Authentik and import again.

### Groups

- Skipped: `Has no members and no app uses it.` Nothing to do, unless you wanted the group. Then add a member in Authentik.
- Warning: `Isn't an admin group in Authentik any more. Keywell leaves admin access and two-step sign in on; untick them on the group's page if that's right.` On the group's page in Keywell, untick "Members can use the admin pages" and "Members must use two-step sign in" if the group should no longer have them. Keywell never takes admin access away on its own, so nobody gets locked out, and while the group has admin access it doesn't turn two-step sign in off either.
- Warning: `Isn't an admin group in Authentik any more. Keywell leaves admin access on; untick it on the group's page if that's right.` The same, for a group whose two-step sign in was already turned off in Keywell.
- Warning: `Is no longer in Authentik. Keywell has left it as it is.` See "Things that disappear from Authentik".

### Apps: skipped

- `Has nothing to sign in with in Authentik.` The app has no login settings in Authentik. If it should sign people in, set that up in Authentik, or add the app by hand in Keywell.
- `Signs in with something other than OpenID Connect, which is all Keywell supports.` The app uses another kind of login. Keywell can't do it. Keep that app on Authentik for now, or change the app.
- `Isn't used by any application in Authentik.` Login settings are left in Authentik that no app uses. Ignore it, unless an app lost its settings by mistake.
- `Identifies people in a way Keywell doesn't support.` Change the app's setting for how it identifies people in Authentik to one of its usual choices, or add the app by hand in Keywell.
- `Another app in Keywell already uses its client ID.` Another app in Keywell has the same client ID. Delete or change one of them.
- A sentence from Keywell's own app checks, such as `Another app already uses that short name.`, `Line … isn't a full web address starting with https:// or http://.`, `Line … can't contain a # part.` or `Add at most 20 addresses.` Fix the app's name or return addresses in Authentik.

For an app that an earlier import already put in Keywell, the line ends with `Who can use it still follows Authentik.` (its other details stay as they were) or `Only admins can use it until you choose its groups on the app's page.`

### Apps: warnings

- `Its short name changed from … to ….` Informational. Keywell uses lower-case letters, numbers and hyphens.
- `Return address … is a pattern. Add the real addresses on the app's page.` Authentik accepted a pattern for the address the app sends people back to. Keywell needs the real addresses, one by one. Add them on the app's page in Keywell afterwards. Until you do, the app can't sign anyone in, so don't skip this one.
- `Sign-out return address … is a pattern. Add the real addresses on the app's page.` Same, for the address people land on after signing out.
- `Identified people by UPN in Authentik. Keywell uses their email address instead.` Check the app copes with that.
- `Its link to open the app isn't a web address Keywell can use, so it was left off.` Add the link on the app's page if you want a tile on the home page.
- `Its icon is stored in Authentik. Upload it on the app's page.`
- `Authentik sent extra details through "…", which Keywell doesn't send.` Someone wrote a custom rule in Authentik that put extra details into the app's login. Keywell doesn't send them. If the app needs them, ask whoever runs the app whether it can use members' metadata instead.
- `Authentik sent group names to it with "profile". Keywell sends them only when an app asks for "groups", so add groups to its scopes if it uses them.` An app that reads group names needs `groups` added to the list of things it asks for (its scopes). For the wiki, see "The wiki" in section 5.
- `Authentik's access tokens lasted …; Keywell's limit is …, so it uses that.` (and the same with `Keywell's minimum is …`) Nothing to do unless the app depended on the other time. You can set the times on the app's page.
- `Authentik kept sign-ins for …; Keywell's limit is …, so it uses that.` (and the same with `Keywell's minimum is …`) Same.
- `Keywell couldn't read how long Authentik's access tokens lasted, so it uses the default.` (and `…how long Authentik kept sign-ins, so it uses the default.`) Same.
- `Authentik limited who could use it …. Only admins can use it until you choose its groups on the app's page.` The `…` is one of: `with a policy`, `with a named person`, `with a rule that left people out`, `with several groups that all had to match`, `with a group Keywell doesn't have`. Keywell can only say "these groups may use this app", so it makes the app admins-only rather than let in anyone Authentik kept out. Either fix the access in Authentik before the final import (for example, replace a rule about one person with a group), or choose the groups on the app's page afterwards.
- `Authentik let it sign in by itself. To allow that in Keywell, choose a service account on the app's page.` See "Apps that sign in by themselves".
- `Is no longer in Authentik. Keywell has left it as it is.` See "Things that disappear from Authentik".

### Apps that sign in by themselves

Some apps ask for a login with nobody there: a script, a door controller, a billing job. In Authentik they use the "client credentials" setting. In Keywell such an app needs a service account, chosen on the app's page.

The report only warns about this when Authentik's list of allowed settings named it. Most apps in Authentik leave that list empty, so the report can say nothing even though the app does sign in by itself. Check each such app by hand. If you don't know which apps do this, ask whoever runs them, or look for sign-ins in their logs with no person behind them.

### Things that disappear from Authentik

Members, groups and apps that an earlier import put into Keywell, and that are no longer in Authentik, are not removed. Keywell leaves them exactly as they are and warns with `Is no longer in Authentik. Keywell has left them as they are.` (members) or `…left it as it is.` (groups and apps). This includes an app deleted in Authentik, an app changed to another kind of login, and an app whose login settings were detached from it. If they shouldn't stay, disable or delete them in Keywell by hand.

## 4. Until the switch

- **Make changes in Authentik, not in Keywell.** Each import overwrites Keywell's copy of the members, groups and apps it imports with what Authentik says. Anything edited on those in Keywell is lost on the next import.
- **Don't change app secrets in Keywell.** An import puts Authentik's secret back.
- **Re-importing resets who can use each app** to what Authentik allows. A rule Keywell can't express becomes admins-only, never wider. So before the final import, either fix the access in Authentik, or plan to choose the app's groups again on its page in Keywell afterwards. One exception: an app you added by hand in Keywell, which the import matched by its client ID but which fails Keywell's checks, keeps the access it has in Keywell.
- **Limits set on Authentik's sign-in steps aren't copied.** Access rules attached to Authentik's sign-in steps, rather than to the app itself, aren't carried over, and the report doesn't mention them. If you used any, set those limits as the app's groups in Keywell.
- Re-run the dry run whenever you like.

## 5. Switch day

Before you start, have open: the Authentik server, the Keywell server and the wiki's server, and the clean report from your last dry run.

1. **Announce a short window** (half an hour is plenty) and ask other admins not to change anything in Authentik until you say so.
2. **Take a fresh copy, copy it to the Keywell server, and restore it there** (section 2, steps 2 and 3, running `docker rm -f ak-copy` on the Keywell server first). Under Docker, join the new `ak-copy` to the Keywell network again.
3. **Run the import for real.** It is the dry-run command without `--dry-run`, with the same `--drop-key` options:

   ```sh
   read -rs PGPASSWORD && export PGPASSWORD   # the new throwaway database's password
   sudo -u keywell --preserve-env=PGPASSWORD keywell import-authentik --config /etc/keywell/keywell.yaml \
     --from postgres://postgres@127.0.0.1:55433/authentik
   ```

   Under Docker, use the compose form from section 2, step 4, without `--dry-run` (with `sudo --preserve-env=PGPASSWORD` in front if you need `sudo` for `docker`). It is safe to do this while `keywell serve` is running. The import locks Keywell's database for as long as it runs, so a sign-in that needs to save something waits a few seconds at most and then carries on.
4. **Check the result.** Sign in to Keywell as an admin and open Settings, then Import from Authentik. It shows when the import ran and the same counts and list as the command printed. Check the counts match your last dry run. Choose groups again on any app the report made admins-only.
5. **Switch the wiki.** See below.
6. **Switch each of your own apps.** See below.
7. **Sign in to each app once** as an ordinary member, to see that it works: the wiki and each of your own apps. Try a member who has an authenticator app, too.
8. **Turn Authentik off,** but keep the last dump file somewhere safe. Then tell people the window is over.

### The wiki

These names were checked against the OpenID Connect extension 8.3.0 documentation on mediawiki.org on 26 October 2026, and the extension's source. If your wiki has an older version, check that version's page.

1. **In Keywell,** open the wiki's page under Applications. It needs the return address `https://wiki.example.org/index.php/Special:PluggableAuthLogin` (your wiki's own address). The import copied it, with the client ID and secret. The Setup details panel on the same page shows the settings below, ready to copy.
2. **In `LocalSettings.php`,** change `providerURL` to Keywell's address, with no `/` at the end:

   ```php
   $wgPluggableAuth_Config['Keywell'] = [
       'plugin' => 'OpenIDConnect',
       'data' => [
           'providerURL' => 'https://login.example.org',
           'clientID' => '…',
           'clientsecret' => '…',
           'scope' => [ 'openid', 'profile', 'email', 'groups' ],
       ],
   ];
   ```

   Add `'groups'` to `scope` only if the wiki turns group names into wiki rights. Without a `scope` setting the extension asks for `openid`, `profile` and `email`.
3. **Tell the wiki who is who.** The wiki remembers each person by the pair of Authentik's address and their ID, in a table called `openid_connect`. Its columns are `oidc_id`, `oidc_user` (the wiki's own user number), `oidc_subject` (their ID) and `oidc_issuer` (Authentik's address). Keywell keeps each app's IDs the same, so `oidc_subject` stays right. Only `oidc_issuer` needs changing.

   Back the table up first. Then use your wiki's database tool (if the wiki uses a table prefix, `$wgDBprefix`, put it in front of the table name) to look at what is there:

   ```sql
   SELECT DISTINCT oidc_issuer FROM openid_connect;
   ```

   It shows Authentik's address for the wiki, for example `https://authentik.example.org/application/o/wiki/`. Write it down, then replace it exactly as shown with Keywell's:

   ```sql
   UPDATE openid_connect
     SET oidc_issuer = 'https://login.example.org'
     WHERE oidc_issuer = 'https://authentik.example.org/application/o/wiki/';
   ```

   Do this during the window, at the same moment as the change to `LocalSettings.php`.
4. **Migrate by email (an extra safety net).** The extension's setting `$wgOpenIDConnect_MigrateUsersByEmail = true;` matches a person to a wiki account with the same email address. It is off by default. Turn it on for the first few weeks. Note that the extension's page says it only matches wiki accounts that have no stored address and ID at all. Accounts already linked to Authentik are not matched by it, which is why the `UPDATE` above is the step that matters for them. The setting helps with wiki accounts that exist but were never linked.
5. Sign in to the wiki as yourself. Check that you reach your own account and not a new one.

### Each of your own apps

For each app:

1. Change the address of the login service to Keywell's. Depending on the app that is called the issuer, the discovery URL, or both:
   - Issuer: `https://login.example.org`
   - Discovery URL: `https://login.example.org/.well-known/openid-configuration`
   - Keys (JWKS) URL: `https://login.example.org/.well-known/jwks.json`

   Use your own Keywell address, which is the app's `public_url`.
2. Keep the client ID and secret the same. The import copied both.
3. Check the return addresses on the app's page in Keywell. If the report said an address was a pattern, add the real ones now.
4. If the app has no client secret (Keywell's list of apps says "No secret (browser or phone app)"), check before the switch that it uses PKCE with the S256 method. Authentik didn't insist on it, but Keywell refuses such an app's sign-ins without it, and refuses PKCE's `plain` method too.
5. Sign in once.

People's IDs (the `sub` value) in these apps don't change, because the import kept each app's way of identifying people. The app's page in Keywell shows a warning triangle about that. That is expected for now.

## 6. If something goes wrong

- **Point the apps back at Authentik.** It still has everything. For the wiki, put `providerURL` back and run the `UPDATE` the other way round, with the old address you wrote down. Members who changed their password in Keywell since the switch use their old one in Authentik.
- **Importing again is safe until anyone changes things in Keywell.** It updates what is already in Keywell and never makes duplicates. But it also puts Authentik's version back over changes made in Keywell since the last import (section 4). After the switch, that means it turns members you turned off in Keywell back on (unless Authentik has them off too), puts Authentik's client secrets back, and resets the members of the imported groups and who can use each app to what Authentik says. Members who have signed in to Keywell keep their Keywell password and two-step sign in. So once people use Keywell, import again only if you are ready to make those changes again.

## 7. A few weeks later

1. Turn off `$wgOpenIDConnect_MigrateUsersByEmail` in the wiki. It is no longer needed.
2. Once an app no longer depends on Authentik's IDs for people, consider switching its identity setting to Keywell's own IDs on the app's page in Keywell (the warning triangle explains it). Check the app first: everyone's ID in it changes.
3. Remove the throwaway database and the dumps:

   ```sh
   docker rm -f ak-copy
   rm authentik.dump
   ```

   Delete the other copies of the dump too, including the one on the server that runs Authentik. Keep one only if you want a last record of Authentik, and keep it private.
4. When you're happy, shut Authentik down for good and remove its data.
