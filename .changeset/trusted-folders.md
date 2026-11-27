---
"@firstdataunion/sentrook-openclaw": patch
---

Trusted folders: `/sentrook-grant folder <dir>` trusts a folder you write and maintain, such as the repository your
jobs' instructions live in. A file the agent reads from it with the `read` tool, unchanged since you set the grant, is
sent with `trusted_by`, and Sentrook reads it as your own words: it no longer makes the chat count as exposed to
untrusted content. Nothing else is relieved. The plugin records the folder when you set the grant (in a git repository
the commit checked out; elsewhere each file's sha256); an edited, new or untracked file, or one reached through a
symlink out of the folder, is not trusted. `--follow origin/main` follows that branch's tip on the remote, asked of the
remote itself. The grant refuses `/`, the home folder and above, wildcards and the agent's and Sentrook's own folders;
it is persistent by default, set only by command or from `/sentrook-setup` (never from the settings or a suggestion),
and `/sentrook-grants` shows what each is pinned to. The setup skill now asks which repositories you maintain and can
propose folder items (`sentrook_propose_setup` takes `kind: folder` and `follow`).
