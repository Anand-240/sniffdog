# SniffDog

SniffDog reads a coding-assignment repository **before you run it**. It looks for commands that could start during installation or when a folder opens in VS Code, hidden code, disguised files, unusual package sources, and other warning signs. It never installs dependencies or executes code from the repository it scans.

Fake hiring exercises have been used to deliver malware to developers. [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/), [Elastic Security Labs](https://security-labs.elastic.co/security-labs/contagious-interview-malware-svg-steganography), and [Socket](https://socket.dev/blog/north-korean-contagious-interview-campaign-drops-35-new-malicious-npm-packages) have documented the Contagious Interview campaign. Cloning a repository usually just copies files; running `npm install`, opening a trusted workspace, or starting the app can run project commands. See [npm lifecycle scripts](https://docs.npmjs.com/cli/v8/using-npm/scripts/) and [VS Code folder-open tasks](https://code.visualstudio.com/docs/debugtest/tasks).

## What it checks

| Area | Examples |
| --- | --- |
| Install and editor triggers | npm lifecycle scripts; VS Code tasks that run when a folder opens |
| Hidden JavaScript | encoded strings, `eval`, code after long whitespace, obfuscated names, child processes, raw IP URLs |
| Disguised files | fonts or images containing JavaScript; scripts or extra content in SVG files |
| Dependencies | custom npm registries, remote packages, lookalike names, unusual lockfile sources, checked-in `node_modules` |
| Optional context | GitHub age and commit history, recruiter scam search results, previous scans and known patterns |

**Rules decide the verdict; Gemma reads the code.** A high-severity rule means DANGER, a medium-severity rule means CAUTION, and no such rules means SAFE. Each reason cites a file and line. The report gives fixed, plain-English consequences for the rules, decodes a small printable payload when possible, and asks local Gemma to describe up to five short code snippets. Gemma cannot lower the verdict. Invalid or unavailable model replies are omitted.

A local model keeps source snippets on your machine, works for local folders without an internet connection after model download, has no per-request API fee, and lets you inspect the prompt and checks in this repository. Remote clones, optional GitHub/recruiter lookups, and optional MongoDB memory still need network access.

## macOS setup

Install Python 3.12 and [Ollama](https://formulae.brew.sh/formula/ollama), then start the local Ollama service and pull the two models:

```sh
brew install python@3.12 ollama
brew services start ollama
ollama pull gemma3:1b
ollama pull nomic-embed-text
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[memory,tracing]"
```

The embedding model is needed only for optional pattern memory. The Gemma model is needed only for snippet descriptions. `--no-llm` works without Ollama. See the [Gemma model](https://ollama.com/library/gemma3) and [nomic embedding model](https://ollama.com/library/nomic-embed-text) pages for model details.

## Use it

```sh
sniffdog demo-repos/safe-assignment --no-llm
sniffdog demo-repos/suspicious-assignment
sniffdog https://github.com/owner/repo --no-llm
sniffdog https://github.com/owner/repo --company "Example Co" --recruiter "Jane Doe"
sniffdog demo-repos/suspicious-assignment --lang hinglish
sniffdog demo-repos/suspicious-assignment --no-llm --json
python3 -m unittest discover -s tests -v
```

The command exits **0** for SAFE, **1** for CAUTION, **2** for DANGER, and **3** if it cannot fetch the repository. A GitHub pull-request workflow runs the deterministic JSON scan when package or editor-task files change and fails on DANGER.

The two `demo-repos/` folders are **harmless imitations**. The suspicious one contains inert examples of all planted signals, including a reserved example IP address and an invalid registry domain. Scan them; do not run their npm scripts.

## Optional memory and tracing

All optional services are off when their environment variables are unset. Use [.env.example](.env.example) as a list of variables to export; SniffDog does not automatically load that file.

- `MONGODB_URI` enables past-scan notes and pattern matching. Run `sniffdog seed` after setting it and pulling `nomic-embed-text`.
- `SENTRY_DSN` enables tracing with span names, timings, status, and numeric counts only. Source code and prompts are removed from transactions.
- `GITHUB_TOKEN` can raise GitHub API limits for remote scans. `SERPAPI_API_KEY` enables optional public recruiter/company searches when you supply names.

For Atlas memory, create a **Vector Search** index named `pattern_index` on database `sniffdog`, collection `patterns`. Its definition is:

```json
{
  "fields": [
    {
      "type": "vector",
      "path": "embedding",
      "numDimensions": 768,
      "similarity": "cosine"
    }
  ]
}
```

The field and dimensions match SniffDog's local embedding code; see [MongoDB's vector index documentation](https://www.mongodb.com/docs/search/index/field-types/vector-type/). Memory stores repository URLs, commit hashes, verdicts, rule names, and short known-technique examples, never scanned source code. It skips cleanly if MongoDB, the index, or Ollama embeddings are unavailable.

## False positives and limits

In a check of three small, well-known public repositories, SniffDog reported:

| Repository | Verdict | Findings |
| --- | --- | --- |
| [MDN todo-react](https://github.com/mdn/todo-react) | SAFE | 0 |
| [MDN Express Local Library](https://github.com/mdn/express-locallibrary-tutorial) | SAFE | 0 |
| [Express generator](https://github.com/expressjs/generator) | CAUTION | 2 medium `process-execution` findings in test code |

None received DANGER. The Express generator result is useful context: test code can call `child_process` legitimately, so read the cited lines before acting on a CAUTION. These results describe the repositories at the time of the check; their contents may change.

SniffDog is a static review aid, not an antivirus or proof of safety. It can miss new tricks, and a rule can flag harmless code. Base64 and hex unwrapping only decode printable text; they do not execute it. Gemma can omit a step or describe code inaccurately, so compare any Gemma sentence with the snippet beside it. For package-focused analysis, see [Socket](https://socket.dev/) and [Datadog GuardDog](https://github.com/DataDog/guarddog).
