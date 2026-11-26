<!--
The disclosure paragraph that every store listing carries: the Hermes catalog description and the OpenClaw package
README (the ClawHub and npm listing). {{details}} is where each listing puts what its plugin does with credentials
and on the machine (docs.py LISTING_DETAILS; for Hermes, disclosure_details in catalog-entry.yaml). After editing,
run `python3 integrations/docs/docs.py sync`. This comment is not copied anywhere.
-->
Disclosure: sends each pending tool call, with its recent inputs and session history, to the hosted Sentrook scan
service (sentrook.firstdataunion.org), run by First International Data Union Ltd. Recognised secrets (API keys,
tokens, passwords) are replaced with placeholders first; other personal data, including other people's, is sent as
it is. The service may pass the call to OpenRouter and TypeSafe (United States) to judge it. The scanner does not
store scan content; metadata logs are kept for up to 60 days. {{details}} Sentrook is a beta and does not guarantee
protection.
