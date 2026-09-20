"use strict";
// Runs only in an operator-owned bare mirror. No customer command, hook,
// driver or worktree is executed. Results outside the envelope are explicit.
const fs = require("node:fs"), crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { sha, assert } = require("./common");
const EMPTY = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const CONFIG = ["core.hooksPath=/dev/null", "core.attributesFile=/dev/null", "merge.renameLimit=7000", "merge.directoryRenames=conflict", "merge.renormalize=false", "protocol.file.allow=never"];
function engine(directory, { binary = "/usr/bin/git", version, sha256, authEnvironment = {}, offline = false } = {}) {
  assert(typeof version === "string" && /^git version 2\./.test(version), "PINNED_GIT_VERSION_REQUIRED");
  assert(typeof sha256 === "string" && crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex") === sha256, "PINNED_GIT_BINARY_MISMATCH");
  const env = { PATH: "/usr/bin:/bin", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_NO_REPLACE_OBJECTS: "1", GIT_ATTR_NOSYSTEM: "1", GIT_ATTR_SOURCE: EMPTY, GIT_TERMINAL_PROMPT: "0", LC_ALL: "C",
    GIT_AUTHOR_NAME: "Merge Proof", GIT_AUTHOR_EMAIL: "reconstruction@invalid", GIT_COMMITTER_NAME: "Merge Proof", GIT_COMMITTER_EMAIL: "reconstruction@invalid",
    ...authEnvironment, ...(offline ? { GIT_NO_LAZY_FETCH: "1", GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "protocol.allow", GIT_CONFIG_VALUE_0: "never" } : {}), GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z", GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z" };
  const run = (args, options = {}) => {
    const r = spawnSync(binary, ["-C", directory, ...CONFIG.flatMap(x => ["-c", x]), ...args], {
      env: { ...env, ...(options.env || {}) }, encoding: "utf8", timeout: 30000, maxBuffer: 8 * 1024 * 1024, input: options.input,
    });
    return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
  };
  const get = (args, options) => { const r = run(args, options); assert(r.code === 0, "GIT_RECONSTRUCTION_UNAVAILABLE"); return r.stdout.trim(); };
  assert(get(["--version"]) === version, "PINNED_GIT_VERSION_MISMATCH");
  assert(Number(version.match(/2\.(\d+)/)?.[1]) >= 46, "GIT_VERSION_OUTSIDE_ENVELOPE");
  assert(get(["rev-parse", "--is-bare-repository"]) === "true", "BARE_MIRROR_REQUIRED");
  const infoAttributes = require("node:path").join(directory, "info", "attributes");
  assert(!fs.existsSync(infoAttributes) || fs.statSync(infoAttributes).size === 0, "LOCAL_ATTRIBUTES_OUTSIDE_ENVELOPE");
  assert(run(["config", "--local", "--get-regexp", "^merge\\..*\\.driver$"]).code === 1, "CUSTOM_MERGE_DRIVER_CONFIGURED");
  get(["mktree"], { input: "" });
  const tree = commit => get(["rev-parse", `${commit}^{tree}`]);
  const entries = commit => get(["ls-tree", "-r", "-z", commit]).split("\0").filter(Boolean).map(line => {
    const tab = line.indexOf("\t"), [mode, type, object] = line.slice(0, tab).split(" ");
    return { mode, type, object, path: line.slice(tab + 1) };
  });
  return { run, get, tree, entries, version };
}
function reconstruct(directory, input, config) {
  const result = { status: "NOT_RECONSTRUCTABLE", method: input.method, base: input.base, head: input.head,
    tree: null, flags: [], strategy: "ort", config: CONFIG, attributes: "EMPTY_TREE", submoduleObjects: "ABSENT", replaceRefs: "DISABLED", steps: [] };
  try {
    assert(sha(input.base) && sha(input.head), "EXACT_INPUT_COMMITS_REQUIRED");
    assert(["merge", "squash", "rebase", "queue"].includes(input.method), "MERGE_METHOD_UNSUPPORTED");
    const g = engine(directory, config); result.gitVersion = g.version; result.gitBinaryDigest = config.sha256;
    const bases = g.get(["merge-base", "--all", input.base, input.head]).split("\n").filter(Boolean);
    assert(bases.length, "UNRELATED_HISTORIES"); result.mergeBases = bases;
    const baseEntries = g.entries(input.base), headEntries = g.entries(input.head), ancestor = g.entries(bases[0]);
    const files = new Map([...baseEntries, ...headEntries].map(e => [e.path, e]));
    const lower = new Set();
    for (const path of files.keys()) { if (lower.has(path.toLowerCase())) result.flags.push("case-collision"); lower.add(path.toLowerCase()); }
    for (const path of new Set([...baseEntries, ...headEntries, ...ancestor].filter(e => e.mode === "160000").map(e => e.path))) {
      const b = baseEntries.find(e => e.path === path)?.object, h = headEntries.find(e => e.path === path)?.object, a = ancestor.find(e => e.path === path)?.object;
      assert(!(b !== a && h !== a && b !== h), "BOTH_SIDES_GITLINK_CHANGED");
      if (b !== h) result.flags.push("gitlink-changed");
    }
    for (const ref of [input.base, input.head]) {
      const diff = g.get(["diff", "--name-status", "--find-renames=50%", bases[0], ref]);
      if (diff.split("\n").some(l => /^R0?(5\d)\s/.test(l))) result.flags.push("near-threshold-rename");
    }
    const merge = (base, head, ancestorOverride, attrSource = EMPTY) => {
      const r = g.run(["merge-tree", "--write-tree", ...(ancestorOverride ? [`--merge-base=${ancestorOverride}`] : []), base, head], { env: { GIT_ATTR_SOURCE: attrSource } });
      assert(!/exhaustive rename detection was skipped/i.test(r.stderr), "RENAME_LIMIT_EXCEEDED");
      assert(r.code === 0, "MERGE_CONFLICT_OR_UNAVAILABLE");
      const tree = r.stdout.split("\n")[0]; assert(sha(tree), "EXPECTED_TREE_UNAVAILABLE"); return tree;
    };
    if (input.method === "rebase") {
      let cur = input.base;
      for (const commit of g.get(["rev-list", "--reverse", "--first-parent", `${input.base}..${input.head}`]).split("\n").filter(Boolean)) {
        const parents = g.get(["rev-list", "--parents", "-n", "1", commit]).split(" ").slice(1);
        assert(parents.length === 1, "REBASE_MERGE_COMMIT_OR_ROOT_UNSUPPORTED");
        const expected = merge(cur, commit, parents[0]);
        if (expected === g.tree(cur)) result.flags.push("become-empty");
        result.steps.push({ commit, parent: parents[0], tree: expected });
        cur = g.get(["commit-tree", expected, "-p", cur, "-m", "reconstruction"]);
      }
      // Provider duplicate dropping is not public; flag a patch-id duplicate.
      if (g.get(["cherry", input.base, input.head]).split("\n").some(l => l.startsWith("-"))) result.flags.push("patch-id-duplicate");
      result.tree = g.tree(cur);
    } else if (input.method === "queue") {
      assert(Array.isArray(input.entries) && input.entries.length > 0 && input.providerOrderConfirmed === true, "QUEUE_MEMBERSHIP_ORDER_UNAVAILABLE");
      let cur = input.base;
      for (const entry of input.entries) {
        assert(sha(entry.head), "QUEUE_ENTRY_UNAVAILABLE");
        const step = reconstruct(directory, { method: "merge", base: cur, head: entry.head }, config);
        assert(step.status === "RECONSTRUCTED", step.reason || "QUEUE_STEP_UNAVAILABLE");
        const providerTree=sha(entry.candidate)?g.tree(entry.candidate):entry.tree||null;
        assert(!entry.tree||!entry.candidate||entry.tree===providerTree,"QUEUE_PROVIDER_TREE_BINDING_MISMATCH");
        const comparison=!sha(providerTree)?"PROVIDER_TREE_UNAVAILABLE":step.tree===providerTree?"MATCH":step.flags.length?"DIVERGED_WITH_CAVEATS":"CANDIDATE_MISMATCH";
        result.flags.push(...step.flags); result.steps.push({ head: entry.head, candidate:entry.candidate||null, tree: step.tree, providerTree, comparison });
        cur = g.get(["commit-tree", step.tree, "-p", cur, "-p", entry.head, "-m", "queue reconstruction"]);
      }
      result.tree = g.tree(cur);
    } else result.tree = merge(input.base, input.head);
    if (bases.length > 1) for (const base of bases) {
      try { if (merge(input.base, input.head, base) !== result.tree) result.flags.push("multi-base-sensitive"); }
      catch { result.flags.push("multi-base-sensitive"); }
    }
    for (const ref of [input.base, input.head]) {
      const attributes = g.entries(ref).filter(e => e.path === ".gitattributes" || e.path.endsWith("/.gitattributes"));
      if (attributes.length) {
        const changedBase = new Set(g.get(["diff", "--name-only", "-z", bases[0], input.base]).split("\0").filter(Boolean));
        const both = g.get(["diff", "--name-only", "-z", bases[0], input.head]).split("\0").filter(p => changedBase.has(p));
        const attrRows = both.length ? g.get(["check-attr", "-z", "--stdin", "merge"], { env: { GIT_ATTR_SOURCE: ref }, input: both.join("\0") + "\0" }).split("\0") : [];
        const custom = attrRows.some((x, n) => n % 3 === 2 && !["", "unspecified", "set", "unset", "text", "binary", "union"].includes(x));
        let probe = null;
        try { probe = merge(input.base, input.head, null, ref); }
        catch { /* A conflicted attribute probe is a caveat, never an expected tree. */ }
        assert(!custom || probe === result.tree, "CUSTOM_DRIVER_ATTRIBUTES_UNSUPPORTED");
        if (probe !== result.tree) result.flags.push("attributes-would-change-result");
      }
    }
    result.flags = [...new Set(result.flags)].sort(); result.status = "RECONSTRUCTED";
    result.comparison = !sha(input.providerTree) ? "PROVIDER_TREE_UNAVAILABLE" : result.tree === input.providerTree ? "MATCH" : result.flags.length ? "DIVERGED_WITH_CAVEATS" : "CANDIDATE_MISMATCH";
    if(result.steps.some(s=>["CANDIDATE_MISMATCH","DIVERGED_WITH_CAVEATS"].includes(s.comparison)))
      result.comparison=result.flags.length?"DIVERGED_WITH_CAVEATS":"CANDIDATE_MISMATCH";
  } catch (e) { result.tree = null; result.reason = e.code || "RECONSTRUCTION_UNAVAILABLE"; }
  return result;
}
module.exports = { reconstruct, engine, EMPTY };
