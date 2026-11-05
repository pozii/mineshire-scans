# mineshire-scans

The checker for resource packs that people upload to Mineshire. It runs as a GitHub Actions workflow and keeps this repository separate from the app: the files it opens come from strangers, and its secrets live here only.

## How it works

1. A person uploads a pack. The Mineshire API checks the zip's file list, then starts the **Scan packs** workflow through the GitHub API (`workflow_dispatch` on branch `main`). The workflow also runs once a day at 04:17 UTC and takes whatever is still waiting.
2. `scan.py` asks the API which packs wait, downloads each one through a one-time link, and checks it:
   - `rules.py`: the structure rules again (the upload link stays valid after the first check, so the file could have been swapped).
   - `unpack.py`: unpacks safely with real byte counts; `.png` and `.ogg` files must start like one.
   - `virus.py`: ClamAV.
   - `pictures.py`: a picture model (`Falconsai/nsfw_image_detection`) looks at `pack.png` and the larger pictures.
3. The verdict goes back to the API (`service.py`): approved, refused with a reason in plain words, or no verdict if something broke, so the pack waits for the next run.

`rules.py` holds the same rules as `api/src/packs/inspect.ts` in the main Mineshire repository. Change one, change the other.

## Setup

Repository secrets (Settings > Secrets and variables > Actions):

| Secret | Value |
|---|---|
| `PACKS_API_URL` | The address of the Mineshire API |
| `PACKS_SCAN_SECRET` | The same text as `PACKS_SCAN_SECRET` on the API's Vercel project |

On the API (Vercel project `mineshire-api`): `PACKS_SCAN_REPO=pozii/mineshire-scans`, `PACKS_SCAN_WORKFLOW=scan-pack.yml`, and a fine-grained token with only **Actions: write** on this repository.

Run by hand: Actions > Scan packs > Run workflow.

## Keep private

Do not make this repository public. The workflow log names packs and the reasons they were refused, and the rules and the picture threshold are not meant to be read by the people they are checked against.
