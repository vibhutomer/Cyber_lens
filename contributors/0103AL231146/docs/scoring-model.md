```md
# Threat Scoring & Verdict Logic Model

---

## 1. Executive Summary

This document defines how Cyber Lens derives a **numeric threat score (0–100)** and a **final verdict** (`benign`, `suspicious`, `malicious`) by aggregating results from multiple threat-intelligence providers.

The model is designed to be:

- Clear and explainable to humans
- Resilient to missing or partial data
- Conservative in high-impact decisions
- Easy to evolve as new providers are added

The intent is **decision support**, not absolute truth.

---

## 2. High-Level Flow
```

IOC Submitted
↓
Provider Responses Collected
↓
Signals Normalized
↓
Signals Combined & Weighted
↓
Final Score Computed (0–100)
↓
Verdict Derived

```

Each stage works independently and tolerates provider failures.

---

## 3. Input Model

Each threat-intelligence provider contributes an **opinion**, not a fact.

A provider response may include:
- Provider name
- Verdict signal (`benign`, `suspicious`, `malicious`, `unknown`)
- Confidence level (how sure the provider is)
- Optional context (detections, abuse reports, tags)

Providers that timeout, error, or do not support the IOC type are ignored.
Missing data does **not** imply benign behavior.

---

## 4. Signal Normalization

All provider verdicts are normalized into a common severity level:

| Provider Signal | Normalized Severity |
|-----------------|---------------------|
| Malicious       | High                |
| Suspicious      | Medium              |
| Unknown         | Low                 |
| Benign          | None                |

This allows different providers to be compared on the same scale.

---

## 5. Scoring Logic

### 5.1 Provider Trust

Providers are not equally reliable.
Each provider is assigned a **trust level**:

- **High trust**: well-established, historically accurate
- **Medium trust**: reliable but narrower in scope
- **Low trust**: noisy or community-driven

Higher-trust providers influence the final score more strongly.

---

### 5.2 Combining Signals

The final threat score reflects:
- Strength of malicious indicators
- Number of independent confirmations
- Trust level of the providers
- Confidence reported by each provider

Guiding principles:
- A single malicious signal is not decisive
- Multiple aligned signals increase certainty
- Strong malicious signals outweigh weak benign ones
- Conflicting signals reduce certainty

The final score always falls between **0 and 100**.

---

## 6. Verdict Thresholds

The numeric score is mapped to a verdict using fixed ranges:

| Score Range | Verdict     | Interpretation |
|------------|-------------|----------------|
| 0–30       | Benign      | No credible threat evidence |
| 31–69      | Suspicious  | Mixed, weak, or uncertain signals |
| 70–100    | Malicious   | Strong and corroborated threat signals |

These thresholds are intentionally conservative.

---

## 7. Example Scenarios

### Scenario 1: Strong Malicious Consensus

**Signals**
- Provider A: malicious (high confidence)
- Provider B: malicious (high confidence)
- Provider C: malicious (medium confidence)

**Outcome**
- Final score: high (≈80–90)
- Verdict: **malicious**

**Reasoning**
Multiple trusted providers independently agree.

---

### Scenario 2: Mixed Signals

**Signals**
- Provider A: benign
- Provider B: suspicious
- Provider C: malicious (medium confidence)

**Outcome**
- Final score: mid-range (≈40–55)
- Verdict: **suspicious**

**Reasoning**
Conflicting opinions prevent a strong conclusion.

---

### Scenario 3: Mostly Benign

**Signals**
- Provider A: benign
- Provider B: benign
- Provider C: suspicious (low confidence)

**Outcome**
- Final score: low (≈10–20)
- Verdict: **benign**

**Reasoning**
Strong benign agreement outweighs weak concern.

---

## 8. Edge Case Handling

### Single Provider Available

When only one provider responds:
- The score is based solely on that signal
- Confidence is reduced due to lack of corroboration
- Verdict is usually **suspicious**, unless confidence is extremely low or high

This avoids overconfidence.

---

### All Providers Fail or Timeout

When no usable data is available:
- Score defaults to a neutral value
- Verdict is **unknown**
- Manual review is recommended

The system does not guess.

---

### Strongly Conflicting Signals

When providers strongly disagree:
- The score trends toward the middle
- Verdict becomes **suspicious**
- Confidence is lowered

This reflects real-world ambiguity.

---

## 9. Trade-offs & Rationale

- **Why not simple averaging?**
  Averages allow noisy providers to distort results.

- **Why a wide “suspicious” range?**
  Most real-world IOCs sit in uncertainty; forcing binary decisions increases false positives.

- **Why conservative defaults?**
  Security decisions have consequences; caution is preferred over false confidence.

---

## 10. Future Enhancements

Possible improvements include:
- Dynamic provider trust based on historical accuracy
- Time-based decay for old intelligence
- IOC-type-specific models (IP vs URL vs hash)
- Analyst feedback loops for continuous tuning

---

## Final Note

This model favors **clarity, caution, and explainability** over opaque complexity.
It is intended to help analysts make better decisions, not to claim absolute certainty.
```
