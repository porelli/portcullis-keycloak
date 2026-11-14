package eu.portcullis.signin;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * A compiled rule (contract §8.1 "Rules"): a group {@code {"op": "all" |
 * "any", "items": [...]}} whose items are method ids or nested groups. The
 * Hub compiles; readers only get compiled rules — no families, depth ≤ 4,
 * at most 48 leaves, 1–8 items per group — and refuse anything else. The
 * evaluation gives the Hub's results ({@code internal/signin} Satisfied /
 * Alternatives; the shared vectors check it).
 */
public final class Rule {
    /** Group levels; the top group is level 1 (families add one level). */
    public static final int MAX_DEPTH = 4;
    /** Leaves per rule: 16 items × a family's 3 members. */
    public static final int MAX_LEAVES = 48;
    /** Items per group. */
    public static final int MAX_ITEMS = 8;

    /** The alternative no rule may have: an authenticator code alone. */
    private static final Set<String> CODE_ONLY = Set.of("totp");

    /** A rule nobody meets, with no alternatives (fail closed). */
    public static final Rule UNMEETABLE = new Rule(null, List.of());

    private sealed interface Node permits Leaf, Group {}

    private record Leaf(int rank) implements Node {}

    private record Group(boolean all, List<Node> items) implements Node {}

    private final Node root; // null for UNMEETABLE
    private final List<Set<String>> alternatives;

    private Rule(Node root, List<Set<String>> alternatives) {
        this.root = root;
        this.alternatives = alternatives;
    }

    /**
     * Parses and validates a compiled rule. Anything that isn't one — a
     * leaf at the top, an unknown op or key, a missing key, an empty or
     * over-full group, a leaf that isn't one of the seven method ids (a
     * family, an amr value, {@code inv}), groups nested deeper than 4
     * levels, more than 48 leaves — is an {@link IllegalArgumentException}.
     * So is a rule with an alternative made of {@code totp} alone (contract
     * §8.1 "Rules": an authenticator code is never a way in by itself; the
     * Hub refuses such a rule on save, and every reader refuses it too).
     */
    public static Rule parse(JsonNode n) {
        if (n == null || !n.isObject()) {
            throw new IllegalArgumentException("a compiled rule must be a group");
        }
        int[] leaves = {0};
        Node root = node(n, 1, leaves);
        if (leaves[0] > MAX_LEAVES) {
            throw new IllegalArgumentException("compiled rule: more than " + MAX_LEAVES + " methods");
        }
        List<Set<String>> alts = new ArrayList<>();
        for (int s : alternatives(root)) {
            alts.add(methodsOf(s));
        }
        if (alts.contains(CODE_ONLY)) {
            throw new IllegalArgumentException("compiled rule: an authenticator code alone is a way in");
        }
        return new Rule(root, Collections.unmodifiableList(alts));
    }

    private static Node node(JsonNode n, int depth, int[] leaves) {
        if (n.isTextual()) {
            int r = Methods.rank(n.textValue());
            if (r < 0) {
                throw new IllegalArgumentException("compiled rule: not a method id");
            }
            leaves[0]++;
            return new Leaf(r);
        }
        if (!n.isObject()) {
            throw new IllegalArgumentException("compiled rule: an item must be a method id or a group");
        }
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("compiled rule: groups nest at most " + MAX_DEPTH + " levels");
        }
        if (n.size() != 2 || !n.has("op") || !n.has("items")) {
            throw new IllegalArgumentException("compiled rule: a group has exactly \"op\" and \"items\"");
        }
        JsonNode op = n.get("op");
        boolean all;
        if (op.isTextual() && op.textValue().equals("all")) {
            all = true;
        } else if (op.isTextual() && op.textValue().equals("any")) {
            all = false;
        } else {
            throw new IllegalArgumentException("compiled rule: \"op\" must be \"all\" or \"any\"");
        }
        JsonNode items = n.get("items");
        if (!items.isArray()) {
            throw new IllegalArgumentException("compiled rule: \"items\" must be an array");
        }
        if (items.isEmpty() || items.size() > MAX_ITEMS) {
            throw new IllegalArgumentException("compiled rule: a group holds 1–" + MAX_ITEMS + " items");
        }
        List<Node> out = new ArrayList<>(items.size());
        for (Iterator<JsonNode> it = items.elements(); it.hasNext(); ) {
            out.add(node(it.next(), depth + 1, leaves));
        }
        return new Group(all, List.copyOf(out));
    }

    /** Whether the methods meet the rule: every item of an all, one of an any. */
    public boolean satisfiedBy(Set<String> methods) {
        if (root == null || methods == null) {
            return false;
        }
        int have = 0;
        for (String m : methods) {
            int r = Methods.rank(m);
            if (r >= 0) {
                have |= 1 << r;
            }
        }
        return satisfied(root, have);
    }

    private static boolean satisfied(Node n, int have) {
        if (n instanceof Leaf l) {
            return (have & (1 << l.rank())) != 0;
        }
        Group g = (Group) n;
        if (g.all()) {
            for (Node it : g.items()) {
                if (!satisfied(it, have)) {
                    return false;
                }
            }
            return true;
        }
        for (Node it : g.items()) {
            if (satisfied(it, have)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The rule's ways to be met: the minimal any-of-all-of form, in the
     * rule's order, each alternative a set of method ids. No alternative is
     * listed twice and none contains another. Empty for {@link #UNMEETABLE}.
     */
    public List<Set<String>> alternatives() {
        return alternatives;
    }

    // Method sets as bit masks, bit i = Methods.IDS[i] (the Hub's methodSet).

    private static List<Integer> alternatives(Node n) {
        if (n instanceof Leaf l) {
            return List.of(1 << l.rank());
        }
        Group g = (Group) n;
        if (!g.all()) {
            List<Integer> out = new ArrayList<>();
            for (Node it : g.items()) {
                out.addAll(alternatives(it));
                out = minimal(out);
            }
            return out;
        }
        List<Integer> out = List.of(0);
        for (Node it : g.items()) {
            List<Integer> a = alternatives(it);
            List<Integer> next = new ArrayList<>(out.size() * a.size());
            for (int x : out) {
                for (int y : a) {
                    next.add(x | y);
                }
            }
            out = minimal(next);
        }
        return out;
    }

    /** Drops duplicates and supersets of another set, keeping first appearance. */
    private static List<Integer> minimal(List<Integer> sets) {
        List<Integer> out = new ArrayList<>();
        for (int i = 0; i < sets.size(); i++) {
            int s = sets.get(i);
            boolean keep = true;
            for (int j = 0; j < sets.size(); j++) {
                if (i == j) {
                    continue;
                }
                int o = sets.get(j);
                if ((o & s) == o && (o != s || j < i)) { // o ⊆ s: s is redundant (first copy of equals kept)
                    keep = false;
                    break;
                }
            }
            if (keep) {
                out.add(s);
            }
        }
        return out;
    }

    private static Set<String> methodsOf(int s) {
        Set<String> out = new LinkedHashSet<>();
        for (int i = 0; i < Methods.IDS.size(); i++) {
            if ((s & (1 << i)) != 0) {
                out.add(Methods.IDS.get(i));
            }
        }
        return Collections.unmodifiableSet(out);
    }

    /** Whether every leaf of the rule is in methods (used by SigninConfig). */
    boolean leavesIn(Set<String> methods) {
        return root != null && leavesIn(root, methods);
    }

    private static boolean leavesIn(Node n, Set<String> methods) {
        if (n instanceof Leaf l) {
            return methods.contains(Methods.IDS.get(l.rank()));
        }
        for (Node it : ((Group) n).items()) {
            if (!leavesIn(it, methods)) {
                return false;
            }
        }
        return true;
    }
}
