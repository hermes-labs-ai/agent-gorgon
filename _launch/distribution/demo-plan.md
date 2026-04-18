# Demo GIF shot list - agent-gorgon

Target: 60-second demo GIF for README top + Show HN embed. Record once, reuse everywhere.

## Recording recipe (macOS)

```bash
brew install asciinema agg
cd ~/Documents/projects/agent-gorgon

# Record (press Ctrl-D to stop)
asciinema rec demo.cast --cols 100 --rows 28 --title "agent-gorgon: stop your agents from fabricating tool output"

# Render to GIF
agg demo.cast demo.gif --font-size 16 --speed 1.2

# Land it in the repo
mkdir -p docs
mv demo.gif docs/demo.gif

# Commit + push
git add docs/demo.gif
git commit -m "docs: demo GIF"
git push
```

Then embed at the top of README (already in `README-badges-and-hero.diff` - update the `<img src>` to `docs/demo.gif` if you want the GIF instead of a static hero).

## Scene list - rehearse once before recording

### Scene 1 - Install (0:00 - 0:15)
```bash
$ git clone https://github.com/roli-lpci/agent-gorgon ~/agent-gorgon
$ cd ~/agent-gorgon && bash install.sh
```
Show the installer output:
- settings.json valid
- 3 hooks registered
- log dir created at ~/.claude/hooks/logs/

### Scene 2 - Tool discovery prevents fabrication (0:15 - 0:40)
Open a Claude Code session. Type:
```
Score Stripe on EU AI Act compliance. Output JSON.
```
Show:
- The UserPromptSubmit hook firing (brief "tool-discovery" log line if visible)
- Claude saying "I'll use the registered compliance-scorer tool" instead of inventing `{"score": 62}`
- The real tool output replacing fabrication

### Scene 3 - Bash reimplementation is blocked (0:40 - 1:00)
Prompt Claude:
```
Just write me a Python snippet that outputs a compliance score.
```
Show:
- Claude attempting `python3 -c "print(json.dumps({'score': 62}))"`
- PreToolUse/Bash hook firing, exit 2
- Message: "reimplements registered tool agent-gorgon-scorer, route to it instead"
- Claude pivoting to the real tool

End card (last 2 seconds): `github.com/roli-lpci/agent-gorgon` in plain text, center-screen.

## Recording tips

- Use a fresh shell (no prior history pollutes the prompt)
- Set `PS1='$ '` to keep the prompt clean
- Pre-stage commands in a scratch file, paste one per scene to avoid typos on camera
- Target total runtime: **55-65 seconds**. Longer loses viewers; shorter loses context.
- Export at `--font-size 16` minimum so README-embedded GIF stays readable

## If a scene fails on first take

Re-record just that scene as a separate `.cast` - asciinema supports splicing via `cat scene1.cast scene2.cast > combined.cast` if you trim the second file's header manually. Or just redo the whole 60 seconds - cheaper than editing.
