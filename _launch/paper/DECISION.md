# Paper Decision - agent-gorgon

## Novelty Signals Found

From `docs/BLUEPRINT.md` and `hooks/stop.py`:

- **Documented incident:** The Stripe EU AI Act scoring failure is a concrete, dated incident with a specific model, task, and verbatim model admission ("I had the rules but didn't act on them"). This is empirically interesting but is N=1.

- **Architecture taxonomy:** The BLUEPRINT.md provides a structured decomposition of why 5 prior defense approaches failed and why the 3-layer architecture works. The reasoning about intervention points (pre-generation vs. execution vs. post-generation) is clear and replicable. Not novel in the academic sense - researchers studying instruction-following failure have covered similar territory - but the systems architecture angle (hook spec as enforcement layer) is practically new.

- **Missing:** No controlled experiment. No measurement of false-positive rate. No A/B comparison of hook vs. no-hook fabrication rate. No cross-model or cross-task evaluation. The test suite (105 tests) validates detection logic correctness, not empirical fabrication reduction.

From `tests/test_user_prompt_submit.py` and `tests/test_stop.py`: Tests are unit tests and integration tests of the hook logic. They do not measure the behavioral outcome (does the model actually invoke the tool when the hook fires?). There is no eval dataset.

## Prior Art Contact

- **Perez et al. (2022) "Ignore Previous Prompt: Attack Techniques for Language Models"** - covers instruction-following failures but focuses on adversarial prompts, not tool invocation choices.
- **Schick et al. (2024) "Toolformer"** - tool use learning, different angle (training-time vs. inference-time enforcement).
- **OpenAI's function calling reliability evaluations** - internal, not published, but the community consensus is that models choose tool vs. generate inconsistently.
- **The Claude Code hooks documentation** - not academic, but this is the spec that agent-gorgon builds on. Any paper would need to cite it.

## Recommendation

**`blog-only`**

## Confidence

**0.30**

What would raise it to `publish-workshop`: A controlled experiment measuring fabrication rate (hook vs. no-hook) across 50+ prompts on a standardized task set, with at least 3 different tool types and 2 model versions. Would need to be run with claude-sonnet-4-6 and at least one other model (e.g., GPT-4o). 2-3 days of eval work. If that data exists, the paper would be appropriate for a systems/safety workshop (SoLaR at NeurIPS, Agent Safety workshop).

## Reasoning

- **No empirical measurement:** The core claim ("3-layer hooks reduce fabrication") is plausible and architecturally sound, but there is no data to back it. A paper without measurements would be rejected at any venue.
- **Not architecturally novel enough alone:** Hook-based enforcement is a natural extension of the Claude Code spec. The specific 3-layer composition is new in practice, but the individual components (pre/post/execution hooks) are obvious given the spec.
- **Good blog material:** The Stripe incident story, the 5-failed-approaches taxonomy, the meta-irony of Claude fabricating agent-gorgon's description during this launch - these are compelling narrative elements for a blog post, not an abstract.
- **Path to paper exists:** If Roli runs a controlled experiment using the 105 existing tests as a starting point (extend to behavioral eval, not just logic correctness), this becomes publishable as a short systems paper at a safety workshop.
