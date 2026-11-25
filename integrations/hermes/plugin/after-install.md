**Next: connect Sentrook to your FIDU account.**

```
hermes sentrook login
```

It prints a link to open on any device, where you sign in or create a free account. Until you do, Sentrook stops every tool call: it never lets an unchecked call through.

Then restart Hermes (`hermes gateway restart`) and run `hermes sentrook verify`.
