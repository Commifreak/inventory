# Signing

Two different kinds of signatures are involved.

## 1. Update signatures (Ed25519) – required for self-updates

Agent binaries are signed with the publisher's Ed25519 key when the image is
built. The public key (`internal/release/keys/official.pub`) is compiled into
every agent. Agents only install updates with a valid signature, so a
compromised server cannot push manipulated binaries.

This key belongs to the **project**, not to an installation: everybody using
the official image gets the same signed agents; their server address is added
to the installer at download time. Self-hosters do not need to do anything.

### Setting up the key (project owner)

```bash
openssl genpkey -algorithm ed25519 -out inventory-release.key
openssl pkey -in inventory-release.key -pubout -out inventory-release.pub
```

- Store the complete content of `inventory-release.key` as GitHub Actions
  secret `RELEASE_SIGNING_KEY` (repository settings → Secrets and variables → Actions).
- Commit `inventory-release.pub` as `internal/release/keys/official.pub`.
- Keep an offline backup of the private key (password manager) and delete the
  local file. If the key is lost, existing agents cannot be updated anymore and
  must be reinstalled once.

**Key rotation:** add the new public key as an additional file in
`internal/release/keys/` (agents trust every embedded key), ship a release
signed with the old key, then switch the secret to the new key and remove the
old public key in a later release.

### Building your own image (forks)

```bash
go run ./cmd/inventory-release keygen -out my-release   # my-release.key / my-release.pub
docker buildx build --secret id=release_signing_key,src=my-release.key \
  --build-arg EXTRA_TRUSTED_KEY="$(openssl pkey -pubin -in my-release.pub -outform DER | tail -c 32 | base64)" .
```

Images built without a key contain unsigned agents: installation works,
automatic updates are refused.

## 2. Code signing (Authenticode) – planned

Windows installers are currently **not** code-signed. Consequences:

- SmartScreen warns once when the downloaded installer is started
  (*More info → Run anyway*). Self-updates are not affected: they are
  downloaded by the service and carry no "downloaded from the internet" mark.
- Windows 11 *Smart App Control* (active on some fresh installations) blocks
  unsigned programs completely.
- Antivirus heuristics may flag an unsigned agent. If Microsoft Defender does,
  submit the file as a false positive (role *Software developer*):
  <https://www.microsoft.com/en-us/wdsi/filesubmission>

The architecture already supports signing: a signed binary stays signed for
every server, because the installer configuration is stored in the
unauthenticated part of the file (planned: inside the certificate table, as
Google does for Chrome installers). Options for a private person in Germany:

| Option | Notes |
|---|---|
| Certum Open Source Code Signing (cloud/SimplySign) | cheap; requires a public open source repository (this repository is public now); automation is fiddly |
| SSL.com individual validation + eSigner | automatable in GitHub Actions; considerably more expensive |
| Azure Artifact Signing | currently only for organisations / individuals in the US and Canada |

macOS: installation via the terminal command is not affected by Gatekeeper.
Notarised builds (Apple Developer Program) can be added to CI with `rcodesign`.
