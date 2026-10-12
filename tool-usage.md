# Tool Usage in the Claude Code Sessions for cryptomator-cli

Analyzed: 341 transcript files (main sessions and subagents, excluding the current session) containing 14,462 tool calls. Duplicate entries from resumed sessions were removed via the tool-use ID.

**Legend:** *Failed* = tool result flagged with `is_error` (e.g. non-zero exit code, invalid input, file not found). *Rejected* = blocked by the user or the auto-mode classifier. For Bash, the first real command in a chain is counted (`cd`, `echo`, variable assignments and wrappers such as `timeout` are skipped). A `grep` without matches returns exit code 1 and is therefore also counted as failed.

## Overview per Tool

| Tool | Calls | Failed | Rejected | Failure Rate |
|---|---:|---:|---:|---:|
| Bash | 11834 | 186 | 14 | 1.7 % |
| Edit | 1098 | 6 | 0 | 0.5 % |
| Read | 783 | 10 | 0 | 1.3 % |
| Agent | 330 | 4 | 0 | 1.2 % |
| Write | 219 | 0 | 0 | 0.0 % |
| WebFetch | 79 | 0 | 0 | 0.0 % |
| ccd_session: mark_chapter | 28 | 0 | 0 | 0.0 % |
| Skill | 17 | 0 | 0 | 0.0 % |
| AskUserQuestion | 11 | 0 | 0 | 0.0 % |
| ToolSearch | 11 | 0 | 0 | 0.0 % |
| Grep | 9 | 0 | 0 | 0.0 % |
| WebSearch | 8 | 0 | 0 | 0.0 % |
| SendUserFile | 7 | 0 | 0 | 0.0 % |
| ReportFindings | 6 | 0 | 0 | 0.0 % |
| Monitor | 5 | 1 | 0 | 20.0 % |
| PushNotification | 3 | 0 | 0 | 0.0 % |
| Browser: computer | 3 | 1 | 0 | 33.3 % |
| Browser: browser_batch | 3 | 1 | 0 | 33.3 % |
| Artifact | 2 | 0 | 0 | 0.0 % |
| ExitPlanMode | 1 | 0 | 0 | 0.0 % |
| SendMessage | 1 | 1 | 0 | 100.0 % |
| visualize: read_me | 1 | 0 | 0 | 0.0 % |
| visualize: show_widget | 1 | 0 | 0 | 0.0 % |
| Browser: preview_start | 1 | 0 | 0 | 0.0 % |
| Browser: javascript_tool | 1 | 0 | 0 | 0.0 % |
| **Total** | **14462** | **210** | **14** | **1.5 %** |

## Detail: Tool and Subtool

| Tool | Subtool | Calls | Failed | Rejected | Failure Rate |
|---|---|---:|---:|---:|---:|
| Bash | `grep` | 2556 | 38 | 0 | 1.5 % |
| Bash | `sed` | 2111 | 31 | 1 | 1.5 % |
| Bash | `cargo` | 1655 | 17 | 3 | 1.2 % |
| Bash | `cat` | 1568 | 29 | 1 | 1.9 % |
| Bash | `git` | 1198 | 12 | 1 | 1.1 % |
| Edit | – | 1098 | 6 | 0 | 0.5 % |
| Bash | `python3` | 869 | 7 | 0 | 0.8 % |
| Read | – | 783 | 10 | 0 | 1.3 % |
| Bash | `ls` | 387 | 17 | 0 | 4.4 % |
| Agent | general-purpose | 326 | 4 | 0 | 1.2 % |
| Write | – | 219 | 0 | 0 | 0.0 % |
| Bash | `unzip` | 152 | 4 | 0 | 2.6 % |
| Bash | `review-package` | 142 | 0 | 0 | 0.0 % |
| Bash | `wc` | 140 | 1 | 0 | 0.7 % |
| Bash | `awk` | 93 | 1 | 0 | 1.1 % |
| Bash | `rm` | 86 | 2 | 0 | 2.3 % |
| Bash | `find` | 84 | 2 | 0 | 2.4 % |
| WebFetch | – | 79 | 0 | 0 | 0.0 % |
| Bash | `cp` | 75 | 0 | 1 | 1.3 % |
| Bash | `mkdir` | 73 | 2 | 0 | 2.7 % |
| Bash | `tail` | 66 | 0 | 0 | 0.0 % |
| Bash | `gh` | 63 | 1 | 0 | 1.6 % |
| Bash | `echo/cd (only)` | 38 | 1 | 0 | 2.6 % |
| Bash | `pgrep` | 32 | 1 | 0 | 3.1 % |
| Bash | `mount` | 31 | 0 | 0 | 0.0 % |
| Bash | `head` | 30 | 0 | 0 | 0.0 % |
| Bash | `crypto` | 29 | 2 | 0 | 6.9 % |
| Bash | `mktemp` | 28 | 1 | 0 | 3.6 % |
| ccd_session: mark_chapter | – | 28 | 0 | 0 | 0.0 % |
| Bash | `node` | 23 | 2 | 0 | 8.7 % |
| Bash | `ruby` | 22 | 2 | 0 | 9.1 % |
| Bash | `curl` | 18 | 2 | 0 | 11.1 % |
| Bash | `diff` | 18 | 3 | 0 | 16.7 % |
| Bash | `rustup` | 18 | 1 | 0 | 5.6 % |
| Bash | `sleep` | 18 | 1 | 7 | 44.4 % |
| Bash | `mvn` | 14 | 0 | 0 | 0.0 % |
| Bash | `perl` | 13 | 0 | 0 | 0.0 % |
| Bash | `printf` | 12 | 0 | 0 | 0.0 % |
| Bash | `security` | 12 | 1 | 0 | 8.3 % |
| AskUserQuestion | – | 11 | 0 | 0 | 0.0 % |
| ToolSearch | – | 11 | 0 | 0 | 0.0 % |
| Bash | `limactl` | 10 | 0 | 0 | 0.0 % |
| Bash | `seq` | 9 | 0 | 0 | 0.0 % |
| Bash | `touch` | 9 | 0 | 0 | 0.0 % |
| Grep | – | 9 | 0 | 0 | 0.0 % |
| Bash | `brew` | 8 | 0 | 0 | 0.0 % |
| Bash | `rg` | 8 | 0 | 0 | 0.0 % |
| Bash | `which` | 8 | 0 | 0 | 0.0 % |
| WebSearch | – | 8 | 0 | 0 | 0.0 % |
| Bash | `javap` | 7 | 0 | 0 | 0.0 % |
| SendUserFile | – | 7 | 0 | 0 | 0.0 % |
| ReportFindings | – | 6 | 0 | 0 | 0.0 % |
| Bash | `java` | 5 | 0 | 0 | 0.0 % |
| Bash | `kill` | 5 | 0 | 0 | 0.0 % |
| Bash | `time` | 5 | 0 | 0 | 0.0 % |
| Monitor | – | 5 | 1 | 0 | 20.0 % |
| Bash | `date` | 4 | 0 | 0 | 0.0 % |
| Bash | `pkill` | 4 | 0 | 0 | 0.0 % |
| Bash | `ps` | 4 | 0 | 0 | 0.0 % |
| Bash | `python` | 4 | 0 | 0 | 0.0 % |
| Bash | `shasum` | 4 | 0 | 0 | 0.0 % |
| Bash | `spike_keychain` | 4 | 0 | 0 | 0.0 % |
| Bash | `tar` | 4 | 0 | 0 | 0.0 % |
| Agent | Explore | 3 | 0 | 0 | 0.0 % |
| Bash | `man` | 3 | 0 | 0 | 0.0 % |
| Bash | `mandoc` | 3 | 1 | 0 | 33.3 % |
| Bash | `rustc` | 3 | 0 | 0 | 0.0 % |
| Bash | `sh` | 3 | 0 | 0 | 0.0 % |
| Bash | `task-brief` | 3 | 0 | 0 | 0.0 % |
| Browser: browser_batch | – | 3 | 1 | 0 | 33.3 % |
| Browser: computer | screenshot | 3 | 1 | 0 | 33.3 % |
| PushNotification | – | 3 | 0 | 0 | 0.0 % |
| Skill | superpowers:brainstorming | 3 | 0 | 0 | 0.0 % |
| Skill | superpowers:systematic-debugging | 3 | 0 | 0 | 0.0 % |
| Skill | superpowers:writing-plans | 3 | 0 | 0 | 0.0 % |
| Artifact | publish | 2 | 0 | 0 | 0.0 % |
| Skill | superpowers:subagent-driven-development | 2 | 0 | 0 | 0.0 % |
| Agent | Plan | 1 | 0 | 0 | 0.0 % |
| Browser: javascript_tool | – | 1 | 0 | 0 | 0.0 % |
| Browser: preview_start | – | 1 | 0 | 0 | 0.0 % |
| ExitPlanMode | – | 1 | 0 | 0 | 0.0 % |
| SendMessage | – | 1 | 1 | 0 | 100.0 % |
| Skill | anthropic-skills:pptx | 1 | 0 | 0 | 0.0 % |
| Skill | archify | 1 | 0 | 0 | 0.0 % |
| Skill | artifact-design | 1 | 0 | 0 | 0.0 % |
| Skill | superpowers:dispatching-parallel-agents | 1 | 0 | 0 | 0.0 % |
| Skill | superpowers:finishing-a-development-branch | 1 | 0 | 0 | 0.0 % |
| Skill | superpowers:test-driven-development | 1 | 0 | 0 | 0.0 % |
| visualize: read_me | – | 1 | 0 | 0 | 0.0 % |
| visualize: show_widget | – | 1 | 0 | 0 | 0.0 % |
| Bash | *other (38 commands with < 3 calls)* | 43 | 4 | 0 | 9.3 % |

<details><summary>Other Bash commands</summary>

`actionlint`, `basename`, `bash`, `check`, `cmp`, `CP`, `dirname`, `docker`, `du`, `file`, `go-nfsv4`, `groff`, `health`, `java_home`, `local`, `log`, `nl`, `nm`, `npm`, `podman`, `pwd`, `qlmanage`, `remove`, `rmdir`, `sample`, `sdd-workspace`, `settings.json`, `sort`, `spike_macos_dlopen`, `stat`, `tee`, `test`, `umount`, `unset`, `vault`, `workflows-6a05c36d2c467acf`, `xtask`, `xxd`

</details>
