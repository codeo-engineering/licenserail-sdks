# licenserail CLI

Single static binary (Go, no dependencies). Command `licenserail`, alias `lr`.

```
go install github.com/codeo-engineering/licenserail-sdks/cli@latest   # or download a release binary
licenserail login                       # emailed 6-digit code; the first sign-in creates your organization and a Test key
licenserail products create --code my-app --name "My App"
licenserail customers create --name "Acme"
licenserail licenses create --product prod_... --customer cus_... --seats 3 --feature export
licenserail test activate --product my-app
licenserail init typescript --product my-app
licenserail mcp config --client claude
```

`--json` prints stable machine output for agents. Writes send an `Idempotency-Key`. In Live, irreversible actions print an
approval URL; after a person approves in the dashboard, repeat the command with `--approval apr_...`.
Config: `~/.config/licenserail/config.json` (`%APPDATA%\licenserail` on Windows). Env overrides: `LICENSERAIL_API_KEY`,
`LICENSERAIL_ENV`, `LICENSERAIL_API_URL`.
