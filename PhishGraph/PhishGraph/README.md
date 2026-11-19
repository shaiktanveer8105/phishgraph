# PhishGraph — Phishing Campaign Clustering Using Graph Learning (Java / Swing)

Research Project 05 (CTI). Groups phishing incidents into campaigns from **infrastructure evidence**
(domain, IP, certificate) and compares simple baselines against graph embeddings.
**Clusters are infrastructure-based groupings, not claims about attacker identity.** Shared hosting can
join unrelated campaigns; edges are evidence, not proof of common ownership.

## Graph model
Nodes: URL, DOMAIN, IP, CERT. Edges: URL–DOMAIN, URL–IP, URL–CERT (each carries timestamp + source for provenance).
Planned extension: REPORT nodes, certificate/registrar nodes, VirusTotal relations.

## Methods (implemented)
| Method | Class |
|---|---|
| Jaccard + connected components | `JaccardComponents` |
| IDF-weighted Jaccard (hub-aware) + connected components | `IdfJaccardComponents` |
| DBSCAN over Jaccard distance | `DbscanJaccard` |
| Node2Vec (biased walks + SGNS) → DBSCAN (cosine) | `Node2VecClusterer` |
| GraphSAGE / heterogeneous GNN | **TODO** (needs reliable labels + enough data) |

## Metrics
ARI, NMI, pairwise P/R/F1, B-cubed F1, purity (`Metrics`). Noise points are treated as singleton clusters.

## Build & run (Windows, JDK 17+)
```
build.bat
run.bat            # GUI
run.bat --cli      # headless experiment
package-exe.bat    # optional .exe app image via jpackage
```

## Data
CSV header: `url,domain,ip,cert,timestamp,source,campaign` (`campaign` = ground-truth label, may be empty).
`data/sample_synthetic.csv` is **synthetic** (12 campaigns, 25% of incidents on shared hosting) — a smoke test only.

### TODO for the real study
- [ ] Collect URLhaus / PhishTank (check terms) + public CTI reports; record version, download date, license.
- [ ] Build defensible campaign labels (report-derived or expert-annotated); document the process.
- [ ] Deduplicate before splitting; use temporal split (`DataSource.temporalSplit`); keep final test set untouched.
- [ ] Tune hyperparameters on train only (defaults here were chosen on synthetic data).
- [ ] Add GraphSAGE/R-GCN; ablations for RQ3; error analysis with analyst review.
- [ ] Fixed seeds are in code (`42`); record JDK version in results.

## Research questions
RQ1 graph vs strongest baseline · RQ2 robustness (missing edges `dropObservations`, time windows, source shift) · RQ3 component ablation.

## Observed on synthetic data (seed 1)
Node2Vec+DBSCAN ARI 0.75 vs 0.32 for the best simple baseline at full observation. Under missing observations,
Jaccard variants can look better at low drop rates because dropped fields shrink feature sets — an artifact to analyze, not a finding.
