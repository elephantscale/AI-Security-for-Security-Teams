# AI Security for WAF Specialists Labs

Welcome to the hands-on labs.

## Lab Sequence

1. 01-Introduction
2. 02-Prompt-Injection
3. 03-WAF-Basics
4. 04-Detection
5. 05-WAF-Testing
6. 06-Mitigation
7. 07-Capstone
8. 08-Challenge

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
