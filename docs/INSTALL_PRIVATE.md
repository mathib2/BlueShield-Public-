# Installing from the private repository

The private repo (`pineconegoat/BlueShield`) tracks the same code as the public
mirror (`mathib2/BlueShield-Public-`). Install from the mirror unless you
specifically need an unreleased branch. When you do need the private side,
choose whichever authentication path fits your setup.

## Option A — GitHub personal access token

Fastest for a one-off install.

1. Create a token at <https://github.com/settings/tokens> with the `repo` scope.
2. Run on the Pi:

   ```bash
   sudo INSTALL_TOKEN=ghp_yourtoken_here \
        REPO_URL=https://github.com/pineconegoat/BlueShield.git \
        bash -c "$(curl -fsSL -H 'Authorization: token ghp_yourtoken_here' \
            https://raw.githubusercontent.com/pineconegoat/BlueShield/master/scripts/install.sh)"
   ```

The token is spliced into the clone URL only for the clone step; the installer
removes it from `/opt/blueshield/.git/config` afterwards so it is not left on
the filesystem.

## Option B — SSH deploy key

Recommended for headless Pis. A deploy key is a per-repo, read-only SSH key
that does not require your account's 2FA. Setup is one-time.

```bash
# On the Pi, as the user that will own /opt/blueshield (default: pi)
ssh-keygen -t ed25519 -f ~/.ssh/blueshield_deploy -N "" -C "blueshield-pi"
cat ~/.ssh/blueshield_deploy.pub
```

Copy the printed public key and add it at
<https://github.com/pineconegoat/BlueShield/settings/keys> → **Add deploy key**
(read-only is fine). Then on the Pi:

```bash
cat >> ~/.ssh/config <<'EOF'
Host github-blueshield
    HostName github.com
    User git
    IdentityFile ~/.ssh/blueshield_deploy
    IdentitiesOnly yes
EOF

sudo REPO_URL=git@github-blueshield:pineconegoat/BlueShield.git \
     bash scripts/install.sh
```

Future updates then need no token: `cd /opt/blueshield && sudo git pull` uses
the deploy key automatically.

## Option C — install from a local checkout

If you already have the private repo cloned by any method, run `install.sh` from
inside it. The installer detects a local checkout and copies it to
`/opt/blueshield` without contacting GitHub:

```bash
git clone git@github.com:pineconegoat/BlueShield.git
cd BlueShield
sudo bash scripts/install.sh
```

This is the simplest path on a Pi that already has your SSH keys configured.
