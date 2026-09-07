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
| Zero-param: running-max lookup | yes | 0.466 | 0.178 | 0.390 | 0.041 |
| Majority class (NORMAL) | yes | 0.465 | 0.127 | 0.388 | 0.000 |
| LSTM (calibrated) | yes | 0.507 | 0.416 | 0.406 | 0.237 |
| XGBoost (per-step) | yes | 0.560 | 0.457 | 0.490 | 0.176 |
| Ensemble LSTM+XGBoost | yes | 0.578 | 0.469 | 0.491 | 0.118 |
| **Ensemble + HMM forward-filter (deployed)** | **yes** | **0.578** | 0.448 | 0.413 | **0.067** |
| Ensemble + HMM offline-viterbi | **NO** | 0.574 | 0.431 | 0.478 | 0.041 |

The deployed model beats the parameter-free ceiling by **+0.112**. The HMM's value is
visible not in accuracy but in the **benign false-positive rate, cut from 11.8% to 6.7%**
at equal accuracy: the transition prior suppresses isolated spurious flips on normal
traffic. The offline Viterbi scores similarly but is non-causal, so it is not deployable.

### Session-level detection (what an operator sees)

Per-request accuracy understates operational value, because many RECON requests are
genuinely indistinguishable from browsing. Measured per attacking session:

| Peak stage of session | caught |
|---|---:|
| RECON | 72% |
| FUZZING | 87% |
| INJECTION | 75% |
| EXPLOITATION | 68% |

Median detection latency: **2 requests** into the peak stage; 60% caught within 3.

---

## Honest limitations

- RECON is the hardest class: recon browsing looks like normal browsing at the HTTP
  level, so it is often only distinguishable in aggregate. This is a property of real
  traffic, not a bug, and it caps per-request accuracy.
- The corpus is 62 capture files; composed sessions recombine real blocks from them, so
  diversity is bounded by what was captured. More captures would raise the ceiling.
- Accuracy is ~0.58, not 0.99. The old 0.99 measured a task a lookup table solved. This
  0.58 measures a genuinely hard, leak-free task, and it is a real number.
