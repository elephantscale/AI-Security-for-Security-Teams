# AI Security for WAF Specialists Labs

Welcome to the hands-on labs.

## Lab Sequence

Labs run in lab order, which follows module order. The course has 10 modules but 8 labs — Modules 2 (OWASP GenAI Top 10) and 9 (Cloud WAFs) are discussion/recap and have no lab.

| Lab | Folder | Module |
|---|---|---|
| Lab 01 | `01-Introduction` | Module 1 |
| Lab 02 | `02-Prompt-Injection` | Module 3 |
| Lab 03 | `03-WAF-Basics` | Module 4 |
| Lab 04 | `04-RAG-Security` | Module 5 |
| Lab 05 | `05-Agent-Security` | Module 6 |
| Lab 06 | `06-Denial-of-Wallet` | Module 7 |
| Lab 07 | `07-Detection` | Module 8 |
| Lab 08 | `08-Layered-Defense` | Module 10 |

Complete the labs in order.

## Getting Started

- First time? See SETUP.md
- Ready to start a lab? See QUICKSTART.md

## Updating (git pull)

Pull the latest changes **before** you start, ideally before creating any virtual environments:

```sh
git pull
```

If you have already run some notebooks, the saved cell outputs count as local changes and `git pull` may complain. Discard those changes and pull:

```sh
git stash      # set aside your local notebook output changes
git pull
git stash pop  # only if you want your local changes back
```

Notes:
- This is a **private** repo over HTTPS — if prompted, use a GitHub **Personal Access Token** as the password (not your account password).
- Your `myenv/` virtual environments and the `.env` file are not tracked by git, so a pull never touches them. If a lab folder is renamed by a pull, just re-run `../setup.sh` in the new folder.
