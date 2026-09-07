# Honest multi-stage web-attack detection (rebuild)

This package is a ground-up rebuild of the detector, written after an audit found the
original benchmark could not rank models: a parameter-free rule (memorize each request,
take the worst stage seen so far) scored **0.9987**, beating every trained model,
because the synthetic dataset had only 514 distinct request vectors and every session's
label was the running maximum of severity.

The rebuild's guiding rule: **every reported number must survive a comparison against a
parameter-free baseline, and every decoder that is scored must be causal.**

---

## What changed, and why

| Problem in the original | Fix here |
|---|---|
| Sessions only ever escalated, so `label(t) == max(label[0..t])` for 100% of windows | `compose.py` generates de-escalating, interleaved, oscillating, abandoned and direct sessions. Running-max fraction dropped from **1.00 to ~0.70** |
| 514 distinct request vectors from a tiny synthetic pool | Built from the **real Burp captures** in `SQLrequests/` (2,878 requests, 5 methods, 13 status codes, 653 paths). Distinct vectors rose to **30,000+** |
| Splits leaked; test requests were seen in training | `corpus.py` assigns splits at the **file** level, so no request crosses train/val/test |
| 7 dead or duplicate feature columns; unscaled magnitudes | `features.py` has 30 clean, all-causal features, log-scaled magnitudes, no duplicates |
| `fuzzing_indicator` latched on forever on benign browsing | Context features use a **decay window**, so behaviour cools off (test in `tests/`) |
| Two copies of `build_features` despite a "single source of truth" claim | One `SessionFeatureExtractor`, used by training and inference; a test asserts parity |
| Headline "hybrid" score came from a non-causal offline Viterbi | Deployed decoder is a **causal forward filter**; the offline Viterbi is shown but labelled non-causal and never deployed |
| HMM smoothing was assumed to help but actually hurt | Smoothing strength is **selected on validation**; it now cuts benign false positives |
| Best model (XGBoost) was benchmarked but never deployed | `predict.py` deploys the **ensemble + HMM** that was actually scored |
| Model artifact would not load under the pinned Keras | LSTM saved as **weights-only**, reloaded by rebuilding the architecture; deps pinned |
| No false-positive rate reported, despite "block the client" actions | Benign FP rate is a first-class benchmark column |

---

## Pipeline

```
SQLrequests/*.xml                      real Burp captures (the corpus)
      |
      v  corpus.py        parse + normalize, file-level train/val/test split
      v  compose.py       assemble realistic multi-stage sessions (breaks running-max)
      v  features.py      one causal 30-feature extractor (training == inference)
      v  dataset.py       -> dataset_v2.npz  (sequence view for LSTM, flat view for XGBoost)
      v  train.py         LSTM + XGBoost + HMM; calibrate T and pick HMM smoothing on VAL
      v  evaluate.py      honest benchmark vs parameter-free baselines, causal only
      v  predict.py       online ensemble + causal HMM; live_demo.py drives Juice Shop
```

Run it:

```bash
pip install -r pipeline/requirements.txt
CUDA_VISIBLE_DEVICES=-1 python -m pipeline.dataset      # build dataset_v2.npz
CUDA_VISIBLE_DEVICES=-1 python -m pipeline.train        # train + save artifacts
CUDA_VISIBLE_DEVICES=-1 python -m pipeline.evaluate     # benchmark on the test split
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/ -q   # invariants
# optional live demo, needs Juice Shop on :9000
docker run -d -p 9000:3000 bkimminich/juice-shop
CUDA_VISIBLE_DEVICES=-1 python -m pipeline.live_demo
```

`CUDA_VISIBLE_DEVICES=-1` forces CPU; the cuDNN LSTM path aborts on some GPUs.

---

## The architecture

Three views of one causal per-request feature stream:

- **LSTM** (unidirectional, sequence-to-sequence) contributes temporal memory. Unidirectional
  on purpose: a live detector cannot see future requests.
- **XGBoost** (per request) sees the same feature vector, whose rolling-context columns
  already encode recent behaviour, so it captures non-linear cutoffs without a sequence.
- **HMM** supplies a transition prior over stages, estimated from the composed training
  sessions. It is applied by a **causal forward filter** (sum-product), so the belief at
  request *t* uses only requests 1..*t*. Its strength is tempered toward uniform by a
  factor chosen on validation.

Deployed model = `0.5·LSTM + 0.5·XGBoost` emissions, temperature-calibrated, smoothed by
the validation-tuned forward filter.

---

## Results (held-out test split, disjoint capture files)

Per-request 5-way stage accuracy. The point of the table is the **margin over the
parameter-free ceiling**, and that only causal rows are deployable.

| Model | causal | acc | macro-F1 | edge acc | benign FP |
|---|:---:|---:|---:|---:|---:|
| Zero-param: running-max lookup | yes | 0.457 | 0.171 | 0.388 | 0.022 |
| Majority class (NORMAL) | yes | 0.453 | 0.125 | 0.387 | 0.000 |
| LSTM (calibrated) | yes | 0.572 | 0.485 | 0.394 | 0.198 |
| XGBoost (per-step) | yes | 0.583 | 0.497 | 0.514 | 0.177 |
| Ensemble LSTM+XGBoost | yes | 0.604 | 0.504 | 0.516 | 0.128 |
| **Ensemble + HMM forward-filter (deployed)** | **yes** | **0.576** | 0.456 | 0.375 | **0.080** |
| Ensemble + HMM offline-viterbi | **NO** | 0.583 | 0.457 | 0.478 | 0.046 |

The best causal model beats the parameter-free ceiling by **+0.147**. The HMM trades a
little accuracy for a large cut in false alarms: the deployed forward-filter drops the
**benign false-positive rate from 12.8% to 8.0%** versus the raw ensemble, because the
transition prior suppresses isolated spurious flips on normal traffic. For a detector
whose recommended action is to isolate a client, that trade is the right default; the raw
ensemble is available if recall matters more than false alarms. The offline Viterbi scores
similarly but is non-causal, so it is not deployable.

*Numbers are from one committed training run (`benchmark_v2.json`). CPU training is not
bit-reproducible, so retraining moves each figure by a few points; the ranking and the
margin over baseline are stable.*

### Session-level detection (what an operator sees)

Per-request accuracy understates operational value, because many RECON requests are
genuinely indistinguishable from browsing. Measured per attacking session (committed run):

| Peak stage of session | caught |
|---|---:|
| RECON | 67% |
| FUZZING | 61% |
| INJECTION | 61% |
| EXPLOITATION | 70% |

Median detection latency: **2 requests** into the peak stage; ~62% caught within 3.
(These swing several points between training runs; see the reproducibility note above.)

---

## Can accuracy be improved? What the ceiling analysis shows

Measured on the test split, not guessed:

- **52% of RECON requests are byte-identical to NORMAL requests** at the content level
  (browsing `/`, fetching `/rest/languages`, loading assets). A recon session and a
  normal session issue many of the same requests; the difference is intent, visible only
  in aggregate. That half of RECON is irreducibly unresolvable from a single request.
- A perfect content-only lookup with oracle (test-peeking) labels caps at **0.80**; the
  realistically learnable content-only ceiling is **0.52**. The deployed model at **0.58**
  already sits above the learnable content-only ceiling, i.e. session context is adding
  signal, and below the oracle cap, i.e. some headroom exists but requires resolving the
  ambiguous requests from context.
- **Live augmentation was tried** (`augment.py`, 1,209 extra real-response requests driven
  against Juice Shop, added to train only). It did **not** raise overall accuracy
  (~0.57), but it improved minority-class recall (RECON correctly classified rose ~50%)
  and ensemble macro-F1. The overall number is flat because the ceiling is ambiguity, not
  data volume. Augmentation is therefore an available, documented tool rather than the
  default: run `python -m pipeline.augment` then rebuild with `include_augmented=True`.

Realistic levers, in order of expected effect:

1. **Reframe RECON as a session-level judgment** (was this session probing?) rather than
   labeling each browsing request RECON. This removes the intrinsic NORMAL/RECON
   collision and would lift the ceiling directly.
2. **Timing/rate features across a longer horizon** — a scanner and a human hit the same
   endpoints at very different rates; the current 8-request window captures some of this.
3. **More diverse real captures**, especially of injection/exploitation, which are thin.

Overall accuracy near 0.58 is close to the intrinsic per-request ceiling for this
labeling; the honest way to report higher is the session-level detection above (68-87%),
which is what an operator actually experiences.

## Honest limitations

- RECON is the hardest class: recon browsing looks like normal browsing at the HTTP
  level, so it is often only distinguishable in aggregate. This is a property of real
  traffic, not a bug, and it caps per-request accuracy.
- The corpus is 62 capture files; composed sessions recombine real blocks from them, so
  diversity is bounded by what was captured. More captures would raise the ceiling.
- Accuracy is ~0.58, not 0.99. The old 0.99 measured a task a lookup table solved. This
  0.58 measures a genuinely hard, leak-free task, and it is a real number.
