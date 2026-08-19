/**
 * Process-forest flattening, shared by the tree pane and the lineage timeline.
 *
 * Pulled out of the components because this is the one piece of frontend logic
 * with enough behaviour to get quietly wrong: which rows survive a filter, which
 * ancestors are kept for context, and what "collapsed" means for a node whose
 * children were filtered away. It is pure, so it is tested directly.
 */
import type { ProcessNode } from "./api";

export interface FlatRow {
  node: ProcessNode;
  depth: number;
  /** True when this node has children that survived the filter. */
  hasChildren: boolean;
  expanded: boolean;
  /** True when the node itself failed the filter and is shown only as an
   *  ancestor of something that passed. */
  contextOnly: boolean;
}

export type Predicate = (n: ProcessNode) => boolean;

const ALL: Predicate = () => true;

/**
 * Depth-first flatten, honouring collapse state and a filter.
 *
 * A node is kept when it matches or when a descendant does. Dropping a
 * non-matching ancestor would detach the match from the lineage that explains
 * it, and the lineage is the entire point of a process tree: `powershell.exe`
 * on its own means nothing, `winword.exe -> powershell.exe` means a great deal.
 */
export function flattenForest(
  roots: ProcessNode[],
  collapsed: ReadonlySet<string>,
  match: Predicate = ALL,
): FlatRow[] {
  const out: FlatRow[] = [];
  const memo = new Map<string, boolean>();

  function subtreeMatches(n: ProcessNode): boolean {
    const hit = memo.get(n.key);
    if (hit !== undefined) return hit;
    // Seed before recursing so a malformed case with a parent cycle terminates
    // instead of blowing the stack.
    memo.set(n.key, false);
    let r = match(n);
    if (!r) {
      for (const c of n.children) {
        if (subtreeMatches(c)) {
          r = true;
          break;
        }
      }
    }
    memo.set(n.key, r);
    return r;
  }

  const walk = (node: ProcessNode, depth: number) => {
    const self = match(node);
    const kept: ProcessNode[] = [];
    for (const c of node.children) if (subtreeMatches(c)) kept.push(c);
    if (!self && kept.length === 0) return;

    const expanded = !collapsed.has(node.key);
    out.push({
      node,
      depth,
      hasChildren: kept.length > 0,
      expanded,
      contextOnly: !self,
    });
    if (expanded) for (const c of kept) walk(c, depth + 1);
  };

  for (const r of roots) if (subtreeMatches(r)) walk(r, 0);
  return out;
}

/** Every key in the forest, for collapse-all. */
export function allKeys(nodes: ProcessNode[], acc: string[] = []): string[] {
  for (const n of nodes) {
    acc.push(n.key);
    allKeys(n.children, acc);
  }
  return acc;
}

/** Keys of nodes that have children, which are the only ones worth collapsing. */
export function branchKeys(nodes: ProcessNode[], acc: string[] = []): string[] {
  for (const n of nodes) {
    if (n.children.length > 0) acc.push(n.key);
    branchKeys(n.children, acc);
  }
  return acc;
}

export function countForest(nodes: ProcessNode[]): number {
  let n = 0;
  for (const x of nodes) n += 1 + countForest(x.children);
  return n;
}

export function findNode(nodes: ProcessNode[], key: string): ProcessNode | null {
  for (const n of nodes) {
    if (n.key === key) return n;
    const hit = findNode(n.children, key);
    if (hit) return hit;
  }
  return null;
}

export function findNodeByPid(nodes: ProcessNode[], pid: number): ProcessNode | null {
  for (const n of nodes) {
    if (n.pid === pid) return n;
    const hit = findNodeByPid(n.children, pid);
    if (hit) return hit;
  }
  return null;
}

/** Ancestors of a node, outermost first, so a selection can be revealed. */
export function pathTo(nodes: ProcessNode[], key: string): ProcessNode[] {
  const trail: ProcessNode[] = [];
  const walk = (n: ProcessNode): boolean => {
    trail.push(n);
    if (n.key === key) return true;
    for (const c of n.children) if (walk(c)) return true;
    trail.pop();
    return false;
  };
  for (const r of nodes) if (walk(r)) return trail;
  return [];
}

/** Text predicate over the fields an analyst actually triages on. */
export function textPredicate(needle: string): Predicate {
  const q = needle.trim().toLowerCase();
  if (!q) return ALL;
  return (n) =>
    n.label.toLowerCase().includes(q) ||
    String(n.pid ?? "").includes(q) ||
    (n.command_line?.toLowerCase().includes(q) ?? false) ||
    (n.image?.toLowerCase().includes(q) ?? false) ||
    (n.user?.toLowerCase().includes(q) ?? false);
}

/** Restrict to processes that started inside a window. */
export function rangePredicate(fromNs: number, toNs: number): Predicate {
  return (n) => {
    const ns = n.started?.ns;
    // A process with no time at all is kept: excluding it would silently hide
    // exactly the processes the collector could not read, which are the ones
    // most likely to matter.
    if (ns === undefined || ns === null) return true;
    return ns >= fromNs && ns <= toNs;
  };
}

export function andPredicates(...ps: Predicate[]): Predicate {
  const real = ps.filter((p) => p !== ALL);
  if (real.length === 0) return ALL;
  return (n) => real.every((p) => p(n));
}
