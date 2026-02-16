Good call to pause. Here's what's wrong with this plan:

**The core problem: vibe coders don't know they need guardrails.**

That's the entire paradox. The people who need this can't self-diagnose, which means they won't search for it, won't install it, and won't understand the value prop even if you show them.

"It catches your mistakes before users see them" — a vibe coder thinks: "what mistakes? it works."

**Specific failure modes:**

1. **Distribution is impossible.** Your target user doesn't read r/webdev or HackerNews. They're on YouTube, TikTok, and ChatGPT. They don't browse npm. They ask AI to build things.

2. **"One line of code" is still one line too many.** If they have to know to add it, they won't. The intervention has to happen *before* or *during* code generation, not after.

3. **No burning hair.** Nothing in the four guards solves a problem the vibe coder is currently feeling. They feel "I can't deploy" or "auth is confusing" — not "my logs are unstructured."

4. **OSS SDK is the wrong form factor.** SDKs are for developers. Vibe coders are users. They want a button, not a package.

**What actually works instead:**

The intervention point is the **AI itself**, not the codebase. The real product is one of these:

- A **prompt/system instruction layer** that makes ChatGPT/Claude generate guarded code by default
- A **GitHub Action / CI bot** that auto-PRs fixes on push (zero effort from the vibe coder)
- A **template/starter kit** that already has all four guards baked in — "start here instead of asking AI from scratch"
- An **AI wrapper** (cursor rules file, Claude project instructions) that enforces guardrails during generation

The winner is probably **opinionated starter templates + CI bot**. The vibe coder clones a repo that already works correctly, and a bot keeps it that way.

The SDK is the wrong layer of the stack for this audience.
