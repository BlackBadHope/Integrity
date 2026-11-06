# Example Uroboros routes

`routes.json` is a route bundle: the `details` of one Seed event, holding three
generic routes in the `uroboros-route/v1` format. Use it as a starting point
for your own catalogue.

Check it before you append it:

```bash
python -m integrity_guardian.uroboros_routes validate examples/uroboros-routes/routes.json
```

Then append the object as the details of one Seed event. The Action Log offers
matching routes at admission. See [docs/UROBOROS.md](../../docs/UROBOROS.md).

## Contributing a route

Routes are shared procedural memory, so treat a contribution like code:

- **Generic.** Keep it generic: no hostnames, addresses, accounts or customer
  data from your environment.
- **No secrets.** `validate` rejects secret-like text. Point to your secret
  store instead.
- **Status.** Use `candidate` until someone other than the author has
  checked the route against real state.
- **Rollback.** State the rollback, or say plainly that there is none.
- **Review.** Contributed routes go through a security review before they
  reach a Stable release. A route is guidance, never authority to act.
