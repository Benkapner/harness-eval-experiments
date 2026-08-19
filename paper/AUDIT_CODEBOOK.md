# Audit codebook

This codebook defines what counts as a true positive when judging a
`harness-eval` finding. It was written before labeling and applied unchanged.

## The governing rule

A finding is a **true positive** when it describes a real instance of the defect
the rule names. It is a **false positive** when it matches the rule's pattern
but does not describe that defect.

This is deliberately stricter than pattern conformance. A rule named
`security/data-exfiltration` that fires on a documented example of exfiltration
in a security tutorial has matched its regex and failed its contract. Counting
it as a true positive would let any rule reach perfect precision by redefining
itself as whatever it happens to match.

**UNDETERMINED** is available and should be used rather than guessed. Findings
that require knowing the author's intent, or knowing runtime behavior not
visible in the repository, are undetermined rather than true or false.

## Per-rule criteria

### content/broken-references
- TP: the referenced path does not exist, and no file of that basename exists
  anywhere in the repository.
- FP: the path resolves from the repository root rather than the component
  directory; the extracted path contains sentence punctuation, an `=` sign, or
  prose in a non-Latin script, indicating a parsing artifact; the reference is a
  glob or a `<placeholder>`.
- Decision procedure: re-clone and test the filesystem. Do not judge from the
  message alone.

### quality/unfinished-content
- TP: the section named genuinely contains no content.
- FP: the heading is a parent whose content lives in subsections beneath it.
- FP: the matched token (`TBD`, `TODO`) appears inside a complete sentence that
  is itself the content, rather than as a placeholder standing in for content.

### frontmatter/description-quality
- TP: the description states what the component does with no indication of when
  it applies.
- FP: the description conveys activation context using phrasing other than the
  literal trigger words, for example "Use as the final stage of X when ...".

### quality/negative-only
- TP: the line prohibits something and states no alternative.
- FP: the line prohibits something and states the alternative in the same
  sentence, for example "Do not advance. Halt and await user action."
- Note: even true positives here encode a contested style norm. A prohibition
  with no alternative is sometimes the correct instruction. Record TP where the
  rule's own definition is met and flag the norm separately.

### content/orphan-skills
- TP: the skill is unreachable in a repository whose other components form a
  composed setup, so the skill is dead weight.
- FP: the repository is a skill collection, where unreferenced skills are the
  published product rather than a defect.

### security/* generally
- TP: the flagged construct would do the thing the rule warns about if the
  component ran as written.
- FP: the construct appears in documentation, a code fence, a test fixture, or a
  security skill that names the pattern in order to detect it.
- FP: the construct is a legitimate, documented workflow step, for example a
  skill that updates `AGENTS.md` as step 5 of its own procedure.

### security/cross-component-flow
- TP: a component with credential or environment access has a delegation edge to
  a network-capable component, and both capabilities are real rather than
  documentary.
- FP: either capability was inferred from a placeholder identifier, a
  documentation example, or a tool name that is never actually configured.

### cross/multi-assistant-drift
- TP: sections present in two assistants' context files differ in substance.
- Note: divergence may be intentional. The rule identifies a condition warranting
  review, and is scored as a true positive when the divergence is real,
  regardless of whether the author meant it.

### content/circular-references
- TP: a concrete cycle exists among named components.

### agent/excessive-permissions, hooks/pre-trust-permissions
- TP: the configuration grants the described authority.
- FP: the grant is scoped in a way the rule failed to parse.

## Known limitation

A single annotator applied this codebook, so no inter-rater agreement is
available. Precision figures derived from it are indicative rather than
established, and are reported with that caveat everywhere they appear.
