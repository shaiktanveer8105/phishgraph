/**
 * PhishGraph - clustering phishing campaigns by shared infrastructure (refactored single-file version).
 * Groups phishing URLs by shared domain / IP / certificate. This is NOT attacker attribution.
 *
 * Build : javac PhishGraph.java
 * Run   : java PhishGraph                  GUI, auto-detects CSV files
 *         java PhishGraph a.csv b.csv      GUI on the given files
 *         java PhishGraph --cli            headless, prints results and writes results.txt
 * Needs : JDK 11+
 *
 * CSV columns: url,domain,ip,cert,timestamp,source,campaign  (campaign = ground-truth label, optional)
 */
import java.awt.*;
import java.io.*;
import java.io.File;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;

public class PhishGraph {

    // ------------------------------------------------------------------ data model

    /** A single phishing sighting. A null attribute means "not observed". */
    static class PhishRecord {
        final int id;
        final String url, domain, ip, cert, source;
        final long ts;
        final String label; // ground-truth campaign, may be null

        PhishRecord(int id, String url, String domain, String ip, String cert,
                    long ts, String source, String label) {
            this.id = id; this.url = url; this.domain = domain; this.ip = ip;
            this.cert = cert; this.ts = ts; this.source = source; this.label = label;
        }

        PhishRecord masked(String newDomain, String newIp, String newCert) {
            return new PhishRecord(id, url, newDomain, newIp, newCert, ts, source, label);
        }
    }

    // ------------------------------------------------------------------ data access

    static class DataLoader {

        static List<PhishRecord> readCsv(File file) throws IOException {
            List<PhishRecord> records = new ArrayList<>();
            try (BufferedReader reader = Files.newBufferedReader(file.toPath())) {
                reader.readLine(); // skip header
                int counter = 0;
                String row;
                while ((row = reader.readLine()) != null) {
                    if (row.isBlank()) continue;
                    String[] c = row.split(",", -1);
                    if (c.length < 7) continue;
                    long ts = 0;
                    try { ts = Long.parseLong(c[4].trim()); } catch (Exception ignored) {}
                    records.add(new PhishRecord(counter++, c[0].trim(), blankToNull(c[1]), blankToNull(c[2]),
                            blankToNull(c[3]), ts, c[5].trim(), blankToNull(c[6])));
                }
            }
            return records;
        }

        static void writeCsv(List<PhishRecord> records, File file) throws IOException {
            try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(file.toPath()))) {
                out.println("url,domain,ip,cert,timestamp,source,campaign");
                for (PhishRecord r : records)
                    out.println(String.join(",", nullToBlank(r.url), nullToBlank(r.domain), nullToBlank(r.ip),
                            nullToBlank(r.cert), String.valueOf(r.ts), nullToBlank(r.source), nullToBlank(r.label)));
            }
        }

        private static String blankToNull(String v) { v = v.trim(); return v.isEmpty() ? null : v; }
        private static String nullToBlank(String v) { return v == null ? "" : v; }

        /** Synthetic data where some records of every campaign use shared hosting (a deliberate trap). */
        static List<PhishRecord> generate(int campaigns, int perCampaign, double sharedRate, long seed) {
            Random rnd = new Random(seed);
            String[] hubIps = {"104.21.0.1", "172.67.0.1", "185.199.0.1"};
            String[] hubCerts = {"CN=cloudflare-shared", "CN=letsencrypt-wildcard"};
            List<PhishRecord> raw = new ArrayList<>();
            int next = 0;
            for (int c = 0; c < campaigns; c++) {
                String label = "CAMP-" + c;
                int domainCount = 2 + rnd.nextInt(3), ipCount = 1 + rnd.nextInt(2);
                String[] domains = new String[domainCount], ips = new String[ipCount];
                for (int i = 0; i < domainCount; i++) domains[i] = "secure-" + c + "-" + i + ".example-phish.top";
                for (int i = 0; i < ipCount; i++) ips[i] = "45." + (c % 250) + "." + i + "." + (1 + rnd.nextInt(250));
                String ownCert = "CN=camp" + c + "-ca-" + rnd.nextInt(3);
                long start = 1_700_000_000L + c * 86400L * 3;
                for (int k = 0; k < perCampaign; k++) {
                    String dom = domains[rnd.nextInt(domainCount)];
                    boolean onHub = rnd.nextDouble() < sharedRate;
                    String ip = onHub ? hubIps[rnd.nextInt(hubIps.length)] : ips[rnd.nextInt(ipCount)];
                    String cert = onHub && rnd.nextBoolean() ? hubCerts[rnd.nextInt(hubCerts.length)] : ownCert;
                    raw.add(new PhishRecord(next, "http://" + dom + "/login/" + Integer.toHexString(rnd.nextInt()),
                            dom, ip, cert, start + rnd.nextInt(86400 * 5), "synthetic", label));
                    next++;
                }
            }
            Collections.shuffle(raw, rnd);
            List<PhishRecord> result = new ArrayList<>();
            for (int i = 0; i < raw.size(); i++) {
                PhishRecord o = raw.get(i);
                result.add(new PhishRecord(i, o.url, o.domain, o.ip, o.cert, o.ts, o.source, o.label));
            }
            return result;
        }

        /** Hides each of domain/ip/cert independently with the given probability. */
        static List<PhishRecord> hideFields(List<PhishRecord> input, double prob, long seed) {
            Random rnd = new Random(seed);
            List<PhishRecord> result = new ArrayList<>();
            for (PhishRecord r : input) {
                String d = rnd.nextDouble() < prob ? null : r.domain;
                String i = rnd.nextDouble() < prob ? null : r.ip;
                String c = rnd.nextDouble() < prob ? null : r.cert;
                result.add(r.masked(d, i, c));
            }
            return result;
        }

        /** Scans the usual folders for .csv files. */
        static List<File> discoverCsv() {
            String[] folders = {"Dataset", "../Dataset", "dataset", "data", "../data", "."};
            Map<String, File> unique = new TreeMap<>();
            for (String folder : folders) {
                File[] hits = new File(folder).listFiles((dir, name) -> name.toLowerCase().endsWith(".csv"));
                if (hits == null) continue;
                for (File f : hits) {
                    try { unique.putIfAbsent(f.getCanonicalPath(), f); } catch (IOException ignored) {}
                }
            }
            return new ArrayList<>(unique.values());
        }

        /** Leakage-safe temporal split: earliest fraction vs. the remainder. */
        static List<List<PhishRecord>> splitByTime(List<PhishRecord> input, double fraction) {
            List<PhishRecord> sorted = new ArrayList<>(input);
            sorted.sort(Comparator.comparingLong(r -> r.ts));
            int cut = (int) (sorted.size() * fraction);
            return List.of(new ArrayList<>(sorted.subList(0, cut)), new ArrayList<>(sorted.subList(cut, sorted.size())));
        }
    }

    // ------------------------------------------------------------------ evaluation

    /** ARI, NMI, pairwise P/R/F1, B-cubed F1 and purity. */
    static class ClusterScores {
        double ari, nmi, pairP, pairR, pairF1, b3F1, purity;
        int clusters;

        static final String[] HEADER = {"Method", "#Clusters", "ARI", "NMI", "Pair P", "Pair R", "Pair F1", "B3 F1", "Purity", "Time"};

        static ClusterScores compute(int[] predicted, String[] truth) {
            int n = predicted.length;
            Map<String, Integer> truthIds = new HashMap<>();
            int[] t = new int[n];
            for (int i = 0; i < n; i++) t[i] = truthIds.computeIfAbsent(String.valueOf(truth[i]), k -> truthIds.size());

            Map<Integer, Integer> predCount = new HashMap<>(), truthCount = new HashMap<>();
            Map<Long, Integer> both = new HashMap<>();
            for (int i = 0; i < n; i++) {
                predCount.merge(predicted[i], 1, Integer::sum);
                truthCount.merge(t[i], 1, Integer::sum);
                both.merge(pairKey(predicted[i], t[i]), 1, Integer::sum);
            }
            double sumBoth = 0, sumPred = 0, sumTruth = 0;
            for (int v : both.values()) sumBoth += choose2(v);
            for (int v : predCount.values()) sumPred += choose2(v);
            for (int v : truthCount.values()) sumTruth += choose2(v);
            double allPairs = choose2(n);

            ClusterScores s = new ClusterScores();
            s.clusters = predCount.size();
            s.pairP = sumPred == 0 ? 0 : sumBoth / sumPred;
            s.pairR = sumTruth == 0 ? 0 : sumBoth / sumTruth;
            s.pairF1 = (s.pairP + s.pairR) == 0 ? 0 : 2 * s.pairP * s.pairR / (s.pairP + s.pairR);

            double expected = sumPred * sumTruth / allPairs, maxIdx = 0.5 * (sumPred + sumTruth);
            s.ari = (maxIdx - expected) == 0 ? 1.0 : (sumBoth - expected) / (maxIdx - expected);

            double hPred = 0, hTruth = 0, mutual = 0;
            for (int v : predCount.values()) { double p = (double) v / n; hPred -= p * Math.log(p); }
            for (int v : truthCount.values()) { double p = (double) v / n; hTruth -= p * Math.log(p); }
            for (Map.Entry<Long, Integer> e : both.entrySet()) {
                int pc = (int) (e.getKey() >> 32), tc = (int) (long) e.getKey();
                double joint = (double) e.getValue() / n;
                mutual += joint * Math.log(joint / (((double) predCount.get(pc) / n) * ((double) truthCount.get(tc) / n)));
            }
            s.nmi = (hPred + hTruth) == 0 ? 1.0 : 2 * mutual / (hPred + hTruth);

            double bPrec = 0, bRec = 0;
            Map<Integer, Integer> bestPerCluster = new HashMap<>();
            for (int i = 0; i < n; i++) {
                int overlap = both.get(pairKey(predicted[i], t[i]));
                bPrec += (double) overlap / predCount.get(predicted[i]);
                bRec += (double) overlap / truthCount.get(t[i]);
                bestPerCluster.merge(predicted[i], overlap, Math::max);
            }
            bPrec /= n; bRec /= n;
            s.b3F1 = (bPrec + bRec) == 0 ? 0 : 2 * bPrec * bRec / (bPrec + bRec);
            double majority = 0;
            for (int v : bestPerCluster.values()) majority += v;
            s.purity = majority / n;
            return s;
        }

        private static long pairKey(int a, int b) { return ((long) a << 32) | (b & 0xffffffffL); }
        private static double choose2(long k) { return k * (k - 1) / 2.0; }
        private static String fmt(double d) { return String.format("%.3f", d); }

        String[] toRow(String name, long ms) {
            return new String[]{name, String.valueOf(clusters), fmt(ari), fmt(nmi), fmt(pairP), fmt(pairR),
                    fmt(pairF1), fmt(b3F1), fmt(purity), ms + " ms"};
        }
    }

    // ------------------------------------------------------------------ clustering methods

    interface ClusterMethod {
        String title();
        /** Returns one cluster id per record, aligned with the input order. */
        int[] assign(List<PhishRecord> data);
    }

    static class Toolkit {
        static Set<String> featureSet(PhishRecord r) {
            Set<String> s = new HashSet<>();
            if (r.domain != null) s.add("d:" + r.domain);
            if (r.ip != null) s.add("i:" + r.ip);
            if (r.cert != null) s.add("c:" + r.cert);
            return s;
        }

        static double jaccard(Set<String> a, Set<String> b) {
            if (a.isEmpty() && b.isEmpty()) return 0;
            int common = 0;
            for (String x : a) if (b.contains(x)) common++;
            return (double) common / (a.size() + b.size() - common);
        }

        interface Distance { double between(int i, int j); }

        /** DBSCAN; noise points are turned into singleton clusters so metrics remain defined. */
        static int[] dbscan(int n, Distance dist, double eps, int minPts) {
            int[] label = new int[n];
            Arrays.fill(label, -2); // -2 = unvisited, -1 = noise
            int next = 0;
            for (int i = 0; i < n; i++) {
                if (label[i] != -2) continue;
                List<Integer> seeds = neighbours(n, dist, i, eps);
                if (seeds.size() < minPts) { label[i] = -1; continue; }
                label[i] = next;
                Deque<Integer> queue = new ArrayDeque<>(seeds);
                while (!queue.isEmpty()) {
                    int j = queue.poll();
                    if (label[j] == -1) label[j] = next;
                    if (label[j] != -2) continue;
                    label[j] = next;
                    List<Integer> more = neighbours(n, dist, j, eps);
                    if (more.size() >= minPts) queue.addAll(more);
                }
                next++;
            }
            for (int i = 0; i < n; i++) if (label[i] < 0) label[i] = next++;
            return label;
        }

        private static List<Integer> neighbours(int n, Distance dist, int i, double eps) {
            List<Integer> found = new ArrayList<>();
            for (int j = 0; j < n; j++) if (dist.between(i, j) <= eps) found.add(j);
            return found;
        }

        static int[] compact(int[] ids) {
            Map<Integer, Integer> map = new HashMap<>();
            int[] out = new int[ids.length];
            for (int i = 0; i < ids.length; i++) out[i] = map.computeIfAbsent(ids[i], k -> map.size());
            return out;
        }

        // union-find helpers
        static int root(int[] parent, int x) {
            while (parent[x] != x) { parent[x] = parent[parent[x]]; x = parent[x]; }
            return x;
        }
        static void merge(int[] parent, int a, int b) { parent[root(parent, a)] = root(parent, b); }
    }

    /** Link records whose feature Jaccard similarity reaches the threshold; clusters = connected components. */
    static class JaccardComponents implements ClusterMethod {
        private final double threshold;
        JaccardComponents(double threshold) { this.threshold = threshold; }
        public String title() { return "Jaccard + ConnComp (t=" + threshold + ")"; }

        public int[] assign(List<PhishRecord> data) {
            int n = data.size();
            List<Set<String>> feats = new ArrayList<>();
            for (PhishRecord r : data) feats.add(Toolkit.featureSet(r));
            int[] parent = new int[n];
            for (int i = 0; i < n; i++) parent[i] = i;
            for (int i = 0; i < n; i++)
                for (int j = i + 1; j < n; j++)
                    if (Toolkit.jaccard(feats.get(i), feats.get(j)) >= threshold) Toolkit.merge(parent, i, j);
            int[] roots = new int[n];
            for (int i = 0; i < n; i++) roots[i] = Toolkit.root(parent, i);
            return Toolkit.compact(roots);
        }
    }

    /** IDF-weighted Jaccard: widely shared infrastructure (CDN IPs, wildcard certs) counts for little. */
    static class IdfJaccardComponents implements ClusterMethod {
        private final double threshold;
        IdfJaccardComponents(double threshold) { this.threshold = threshold; }
        public String title() { return "IDF-Jaccard + ConnComp (t=" + threshold + ")"; }

        public int[] assign(List<PhishRecord> data) {
            int n = data.size();
            List<Set<String>> feats = new ArrayList<>();
            Map<String, Integer> docFreq = new HashMap<>();
            for (PhishRecord r : data) {
                Set<String> s = Toolkit.featureSet(r);
                feats.add(s);
                for (String x : s) docFreq.merge(x, 1, Integer::sum);
            }
            Map<String, Double> weight = new HashMap<>();
            for (Map.Entry<String, Integer> e : docFreq.entrySet())
                weight.put(e.getKey(), Math.log((double) n / e.getValue()));
            int[] parent = new int[n];
            for (int i = 0; i < n; i++) parent[i] = i;
            for (int i = 0; i < n; i++)
                for (int j = i + 1; j < n; j++) {
                    double shared = 0, total = 0;
                    Set<String> a = feats.get(i), b = feats.get(j);
                    for (String x : a) { double w = weight.get(x); total += w; if (b.contains(x)) shared += w; }
                    for (String x : b) if (!a.contains(x)) total += weight.get(x);
                    if (total > 0 && shared / total >= threshold) Toolkit.merge(parent, i, j);
                }
            int[] roots = new int[n];
            for (int i = 0; i < n; i++) roots[i] = Toolkit.root(parent, i);
            return Toolkit.compact(roots);
        }
    }

    /** DBSCAN over Jaccard distance of the feature sets. */
    static class DbscanJaccard implements ClusterMethod {
        private final double eps; private final int minPts;
        DbscanJaccard(double eps, int minPts) { this.eps = eps; this.minPts = minPts; }
        public String title() { return "DBSCAN-Jaccard (eps=" + eps + ", minPts=" + minPts + ")"; }

        public int[] assign(List<PhishRecord> data) {
            List<Set<String>> feats = new ArrayList<>();
            for (PhishRecord r : data) feats.add(Toolkit.featureSet(r));
            return Toolkit.dbscan(data.size(), (a, b) -> 1.0 - Toolkit.jaccard(feats.get(a), feats.get(b)), eps, minPts);
        }
    }

    /** Heterogeneous graph: record nodes connected to their domain / IP / certificate nodes. */
    static class InfraGraph {
        final List<String> names = new ArrayList<>();
        final Map<String, Integer> nameToId = new HashMap<>();
        final List<List<Integer>> neighbourLists = new ArrayList<>();
        int[] recordNode;      // record index -> node id
        int[][] adj;           // sorted, de-duplicated neighbours
        final Map<Long, long[]> edgeTime = new HashMap<>();
        final Map<Long, String> edgeSource = new HashMap<>();

        static InfraGraph build(List<PhishRecord> data) {
            InfraGraph g = new InfraGraph();
            g.recordNode = new int[data.size()];
            for (int k = 0; k < data.size(); k++) {
                PhishRecord r = data.get(k);
                int u = g.nodeFor("u:" + r.id);
                g.recordNode[k] = u;
                g.connect(u, r.domain == null ? null : "d:" + r.domain, r);
                g.connect(u, r.ip == null ? null : "i:" + r.ip, r);
                g.connect(u, r.cert == null ? null : "c:" + r.cert, r);
            }
            g.adj = new int[g.neighbourLists.size()][];
            for (int v = 0; v < g.adj.length; v++)
                g.adj[v] = g.neighbourLists.get(v).stream().distinct().mapToInt(Integer::intValue).sorted().toArray();
            return g;
        }

        private int nodeFor(String name) {
            Integer id = nameToId.get(name);
            if (id != null) return id;
            nameToId.put(name, names.size());
            names.add(name);
            neighbourLists.add(new ArrayList<>());
            return names.size() - 1;
        }

        private void connect(int u, String entity, PhishRecord r) {
            if (entity == null) return;
            int v = nodeFor(entity);
            neighbourLists.get(u).add(v);
            neighbourLists.get(v).add(u);
            long key = ((long) Math.min(u, v) << 32) | Math.max(u, v);
            edgeTime.put(key, new long[]{r.ts});
            edgeSource.put(key, r.source);
        }

        int size() { return names.size(); }
        boolean adjacent(int a, int b) { return Arrays.binarySearch(adj[a], b) >= 0; }
    }

    /** Node2Vec (biased walks + skip-gram with negative sampling), then DBSCAN on cosine distance. */
    static class Node2VecClusterer implements ClusterMethod {
        private final int dim, walksPerNode, walkLength, window, negatives, epochs;
        private final double p, q, eps;
        private final int minPts;
        private final long seed;

        Node2VecClusterer(int dim, int walksPerNode, int walkLength, double p, double q,
                          double eps, int minPts, long seed) {
            this.dim = dim; this.walksPerNode = walksPerNode; this.walkLength = walkLength;
            this.p = p; this.q = q; this.eps = eps; this.minPts = minPts; this.seed = seed;
            this.window = 5; this.negatives = 5; this.epochs = 3;
        }

        public String title() { return "Node2Vec + DBSCAN (d=" + dim + ", p=" + p + ", q=" + q + ")"; }

        public int[] assign(List<PhishRecord> data) {
            InfraGraph g = InfraGraph.build(data);
            float[][] emb = learnEmbeddings(g);
            int n = data.size();
            float[][] unit = new float[n][];
            for (int k = 0; k < n; k++) unit[k] = toUnit(emb[g.recordNode[k]]);
            return Toolkit.dbscan(n, (a, b) -> 1.0 - dot(unit[a], unit[b]), eps, minPts);
        }

        float[][] learnEmbeddings(InfraGraph g) {
            Random rnd = new Random(seed);
            int N = g.size();
            List<int[]> corpus = new ArrayList<>();
            Integer[] order = new Integer[N];
            for (int i = 0; i < N; i++) order[i] = i;
            for (int round = 0; round < walksPerNode; round++) {
                Collections.shuffle(Arrays.asList(order), rnd);
                for (int start : order) if (g.adj[start].length > 0) corpus.add(randomWalk(g, start, rnd));
            }
            float[][] inVec = new float[N][dim], outVec = new float[N][dim];
            for (float[] row : inVec) for (int d = 0; d < dim; d++) row[d] = (rnd.nextFloat() - 0.5f) / dim;
            long totalSteps = (long) epochs * corpus.size(), done = 0;
            for (int ep = 0; ep < epochs; ep++) {
                Collections.shuffle(corpus, rnd);
                for (int[] walk : corpus) {
                    float lr = (float) Math.max(0.0001, 0.025 * (1.0 - (double) done++ / totalSteps));
                    for (int i = 0; i < walk.length; i++) {
                        int lo = Math.max(0, i - window), hi = Math.min(walk.length - 1, i + window);
                        for (int j = lo; j <= hi; j++) {
                            if (j == i) continue;
                            update(inVec[walk[i]], outVec[walk[j]], 1f, lr);
                            for (int k = 0; k < negatives; k++) {
                                int neg = rnd.nextInt(N);
                                if (neg != walk[j]) update(inVec[walk[i]], outVec[neg], 0f, lr);
                            }
                        }
                    }
                }
            }
            return inVec;
        }

        private void update(float[] a, float[] b, float target, float lr) {
            float score = dot(a, b);
            float grad = (target - 1f / (1f + (float) Math.exp(-Math.max(-8, Math.min(8, score))))) * lr;
            for (int d = 0; d < dim; d++) { float old = a[d]; a[d] += grad * b[d]; b[d] += grad * old; }
        }

        private int[] randomWalk(InfraGraph g, int start, Random rnd) {
            int[] path = new int[walkLength];
            path[0] = start;
            int len = 1;
            while (len < walkLength) {
                int cur = path[len - 1];
                int[] nbrs = g.adj[cur];
                if (nbrs.length == 0) break;
                if (len == 1) { path[len++] = nbrs[rnd.nextInt(nbrs.length)]; continue; }
                int prev = path[len - 2];
                double[] w = new double[nbrs.length];
                double total = 0;
                for (int i = 0; i < nbrs.length; i++) {
                    w[i] = nbrs[i] == prev ? 1.0 / p : (g.adjacent(prev, nbrs[i]) ? 1.0 : 1.0 / q);
                    total += w[i];
                }
                double x = rnd.nextDouble() * total;
                int choice = nbrs.length - 1;
                for (int i = 0; i < nbrs.length; i++) { x -= w[i]; if (x <= 0) { choice = i; break; } }
                path[len++] = nbrs[choice];
            }
            return Arrays.copyOf(path, len);
        }

        private static float dot(float[] a, float[] b) {
            float s = 0;
            for (int i = 0; i < a.length; i++) s += a[i] * b[i];
            return s;
        }

        private static float[] toUnit(float[] v) {
            float norm = (float) Math.sqrt(dot(v, v)) + 1e-9f;
            float[] out = new float[v.length];
            for (int i = 0; i < v.length; i++) out[i] = v[i] / norm;
            return out;
        }
    }

    // ------------------------------------------------------------------ experiments / CLI

    static class Experiment {
        static List<ClusterMethod> allMethods() {
            return List.of(
                new JaccardComponents(0.60),
                new IdfJaccardComponents(0.60),
                new DbscanJaccard(0.30, 2),
                new Node2VecClusterer(32, 10, 40, 1.0, 0.5, 0.10, 3, 42L)
            );
        }

        static class Outcome {
            final String name; final ClusterScores scores; final long millis;
            Outcome(String name, ClusterScores scores, long millis) { this.name = name; this.scores = scores; this.millis = millis; }
        }

        static List<Outcome> runAll(List<PhishRecord> data) {
            String[] truth = data.stream().map(r -> r.label == null ? "?" : r.label).toArray(String[]::new);
            List<Outcome> outcomes = new ArrayList<>();
            for (ClusterMethod m : allMethods()) {
                long begin = System.currentTimeMillis();
                int[] predicted = m.assign(data);
                outcomes.add(new Outcome(m.title(), ClusterScores.compute(predicted, truth), System.currentTimeMillis() - begin));
            }
            return outcomes;
        }

        /** Rows of {missing %, method, ARI, B3 F1} for each hiding rate. */
        static List<String[]> robustness(List<PhishRecord> data, double[] rates) {
            List<String[]> rows = new ArrayList<>();
            for (double rate : rates) {
                List<PhishRecord> degraded = DataLoader.hideFields(data, rate, 7L);
                for (Outcome o : runAll(degraded))
                    rows.add(new String[]{String.format("%.0f%%", rate * 100), o.name,
                            String.format("%.3f", o.scores.ari), String.format("%.3f", o.scores.b3F1)});
            }
            return rows;
        }

        static int distinctCampaigns(List<PhishRecord> data) {
            Set<String> labels = new HashSet<>();
            for (PhishRecord r : data) if (r.label != null) labels.add(r.label);
            return labels.size();
        }

        /** Loads each CSV by file name; unreadable or empty files are skipped with a warning. */
        static Map<String, List<PhishRecord>> loadAll(List<File> files) {
            Map<String, List<PhishRecord>> loaded = new LinkedHashMap<>();
            for (File f : files) {
                try {
                    List<PhishRecord> d = DataLoader.readCsv(f);
                    if (d.isEmpty()) System.err.println("Skipped (no valid rows): " + f);
                    else loaded.put(f.getName(), d);
                } catch (Exception ex) { System.err.println("Skipped " + f + ": " + ex); }
            }
            return loaded;
        }

        static String buildReport(Map<String, List<PhishRecord>> sets) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, List<PhishRecord>> e : sets.entrySet()) {
                List<PhishRecord> d = e.getValue();
                sb.append("=== ").append(e.getKey()).append("  (").append(d.size()).append(" incidents, ")
                  .append(distinctCampaigns(d)).append(" true campaigns) ===\n");
                sb.append(String.join("\t", ClusterScores.HEADER)).append('\n');
                for (Outcome o : runAll(d)) sb.append(String.join("\t", o.scores.toRow(o.name, o.millis))).append('\n');
                sb.append("\nRobustness (missing observations)\nMissing\tMethod\tARI\tB3 F1\n");
                for (String[] row : robustness(d, new double[]{0.1, 0.3, 0.5})) sb.append(String.join("\t", row)).append('\n');
                sb.append('\n');
            }
            return sb.toString();
        }

        /** Headless mode: java PhishGraph --cli [files...]  (no files = auto-discover). */
        static void runCli(String[] args) {
            List<File> files = new ArrayList<>();
            for (String s : args) if (s.toLowerCase().endsWith(".csv")) files.add(new File(s));
            if (files.isEmpty()) files = DataLoader.discoverCsv();
            Map<String, List<PhishRecord>> sets = loadAll(files);
            if (sets.isEmpty()) {
                System.out.println("No CSV files found - using built-in synthetic data.");
                sets.put("synthetic (built-in)", DataLoader.generate(12, 40, 0.25, 1L));
            }
            String report = buildReport(sets);
            System.out.println(report);
            try { Files.writeString(Paths.get("results.txt"), report); System.out.println("Saved results.txt"); }
            catch (IOException ex) { System.err.println("Could not save results.txt: " + ex); }
        }
    }

    // ------------------------------------------------------------------ Swing GUI

    static class App extends JFrame {
        private Map<String, List<PhishRecord>> sets = new LinkedHashMap<>();
        private final List<File> given;
        private final JLabel status = new JLabel("Starting...");
        private final DefaultTableModel resultModel = new DefaultTableModel(prepend("Dataset", ClusterScores.HEADER), 0);
        private final DefaultTableModel robustModel = new DefaultTableModel(new String[]{"Dataset", "Missing", "Method", "ARI", "B3 F1"}, 0);
        private final JTextArea log = new JTextArea(6, 60);

        App(List<File> given) {
            super("PhishGraph - Phishing Campaign Clustering (infrastructure-based, not attacker attribution)");
            this.given = given;
            setDefaultCloseOperation(EXIT_ON_CLOSE);
            JButton rescan = new JButton("Rescan folders & run all");
            JButton load = new JButton("Load other CSV...");
            JButton run = new JButton("Run all methods");
            JButton rob = new JButton("Robustness sweep");
            JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
            for (JButton b : new JButton[]{rescan, load, run, rob}) top.add(b);

            JTabbedPane tabs = new JTabbedPane();
            tabs.add("Results", new JScrollPane(new JTable(resultModel)));
            tabs.add("Robustness", new JScrollPane(new JTable(robustModel)));
            log.setEditable(false);
            JPanel south = new JPanel(new BorderLayout());
            south.add(new JScrollPane(log), BorderLayout.CENTER);
            south.add(status, BorderLayout.SOUTH);
            add(top, BorderLayout.NORTH); add(tabs, BorderLayout.CENTER); add(south, BorderLayout.SOUTH);

            rescan.addActionListener(e -> autoRun());
            load.addActionListener(e -> {
                JFileChooser chooser = new JFileChooser(new File("."));
                if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
                File chosen = chooser.getSelectedFile();
                background(() -> {
                    try {
                        List<PhishRecord> d = DataLoader.readCsv(chosen);
                        if (d.isEmpty()) { info("No valid rows in " + chosen.getName()); return; }
                        sets.put(chosen.getName(), d);
                        info("Loaded " + d.size() + " incidents from " + chosen.getName());
                        fillResults(); fillRobustness();
                    } catch (Exception ex) { showError(ex); }
                });
            });
            run.addActionListener(e -> background(this::fillResults));
            rob.addActionListener(e -> background(this::fillRobustness));
            pack(); setSize(1100, 650); setLocationRelativeTo(null);
        }

        /** Finds the CSV files (or uses the command-line ones) and runs everything. */
        void autoRun() {
            background(() -> {
                List<File> files = given.isEmpty() ? DataLoader.discoverCsv() : given;
                Map<String, List<PhishRecord>> loaded = Experiment.loadAll(files);
                if (loaded.isEmpty()) {
                    loaded.put("synthetic ", DataLoader.generate(12, 40, 0.25, 1L));
                    info("No CSV files found - using built-in synthetic data.");
                } else info("Found " + loaded.size() + " dataset(s): " + loaded.keySet());
                sets = loaded;
                fillResults();
                fillRobustness();
            });
        }

        private void fillResults() {
            Map<String, List<PhishRecord>> snapshot = new LinkedHashMap<>(sets);
            if (snapshot.isEmpty()) { info("No data loaded."); return; }
            setStatus("Running all methods...");
            List<String[]> rows = new ArrayList<>();
            for (Map.Entry<String, List<PhishRecord>> e : snapshot.entrySet())
                for (Experiment.Outcome o : Experiment.runAll(e.getValue()))
                    rows.add(prepend(e.getKey(), o.scores.toRow(o.name, o.millis)));
            SwingUtilities.invokeLater(() -> {
                resultModel.setRowCount(0);
                rows.forEach(resultModel::addRow);
                info("Results ready for " + snapshot.size() + " dataset(s). Clusters = shared infrastructure, not proof of one attacker.");
            });
        }

        private void fillRobustness() {
            Map<String, List<PhishRecord>> snapshot = new LinkedHashMap<>(sets);
            if (snapshot.isEmpty()) return;
            setStatus("Running robustness sweep...");
            List<String[]> rows = new ArrayList<>();
            for (Map.Entry<String, List<PhishRecord>> e : snapshot.entrySet())
                for (String[] r : Experiment.robustness(e.getValue(), new double[]{0.0, 0.1, 0.2, 0.3, 0.5}))
                    rows.add(prepend(e.getKey(), r));
            SwingUtilities.invokeLater(() -> {
                robustModel.setRowCount(0);
                rows.forEach(robustModel::addRow);
                info("Robustness sweep done.");
            });
        }

        private static String[] prepend(String first, String[] rest) {
            String[] out = new String[rest.length + 1];
            out[0] = first;
            System.arraycopy(rest, 0, out, 1, rest.length);
            return out;
        }

        private void background(Runnable task) {
            new Thread(() -> {
                try { task.run(); } catch (Exception ex) { showError(ex); }
            }).start();
        }

        private void setStatus(String s) { SwingUtilities.invokeLater(() -> status.setText(s)); }
        private void info(String s) { SwingUtilities.invokeLater(() -> { status.setText(s); log.append(s + "\n"); }); }
        private void showError(Exception ex) {
            SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(this, ex.toString(), "Error", JOptionPane.ERROR_MESSAGE));
        }
    }

    // ------------------------------------------------------------------ entry point

    public static void main(String[] args) {
        boolean headless = false;
        List<File> given = new ArrayList<>();
        for (String s : args) {
            if (s.equals("--cli")) headless = true;
            else if (s.toLowerCase().endsWith(".csv")) given.add(new File(s));
        }
        if (headless) { Experiment.runCli(args); return; }
        SwingUtilities.invokeLater(() -> {
            App app = new App(given);
            app.setVisible(true);
            app.autoRun();
        });
    }
}
