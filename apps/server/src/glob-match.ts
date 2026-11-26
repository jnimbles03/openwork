// Glob matching for config-supplied patterns. Patterns are compiled to an NFA
// and simulated state-set at a time, so matching costs at most
// O(pattern length * input length) regardless of how wildcards are arranged.
// Regex-backed matchers (minimatch included) backtrack and can be stalled by
// crafted patterns, which is not acceptable for input written by collaborators.
//
// Supported syntax: `*`, `?`, `**` path segments, `[...]` classes (with `!`/`^`
// negation and ranges), `{a,b}` alternation, `\` escapes, a leading `!` to
// negate, and a leading `#` for comments (never matches).
//
// Matchers sharing a budget stop matching (return false) once it is spent, so
// callers can bound total work across many patterns and inputs.

const MAX_PATTERN_LENGTH = 256;

export type GlobBudget = { remaining: number };

type Ast =
  | { kind: "char"; test: (c: string) => boolean }
  | { kind: "star" }
  | { kind: "globstar" }
  | { kind: "globstarDir" }
  | { kind: "alt"; options: Ast[][] };

type State =
  | { kind: "char"; test: (c: string) => boolean; next: number }
  | { kind: "split"; next: number; alt: number }
  | { kind: "match" };

const notSlash = (c: string) => c !== "/";
const anyChar = () => true;

function findClassEnd(pattern: string, open: number, end: number): number {
  let i = open + 1;
  if (pattern[i] === "!" || pattern[i] === "^") i += 1;
  if (pattern[i] === "]") i += 1;
  for (; i < end; i += 1) {
    if (pattern[i] === "\\") {
      i += 1;
      continue;
    }
    if (pattern[i] === "]") return i;
  }
  return -1;
}

function parseClass(pattern: string, open: number, close: number): (c: string) => boolean {
  let i = open + 1;
  const negated = pattern[i] === "!" || pattern[i] === "^";
  if (negated) i += 1;
  const ranges: Array<[string, string]> = [];
  while (i < close) {
    let lo = pattern[i];
    if (lo === "\\" && i + 1 < close) {
      i += 1;
      lo = pattern[i];
    }
    i += 1;
    let hi = lo;
    if (pattern[i] === "-" && i + 1 < close) {
      i += 1;
      hi = pattern[i];
      if (hi === "\\" && i + 1 < close) {
        i += 1;
        hi = pattern[i];
      }
      i += 1;
    }
    ranges.push([lo, hi]);
  }
  return (c) => {
    if (c === "/") return false;
    const inClass = ranges.some(([lo, hi]) => c >= lo && c <= hi);
    return negated ? !inClass : inClass;
  };
}

// Returns the closing brace index and top-level comma positions, or null when
// the brace is unterminated or has no comma (then it is a literal `{`).
function scanBrace(pattern: string, open: number, end: number): { close: number; commas: number[] } | null {
  let depth = 0;
  const commas: number[] = [];
  for (let i = open + 1; i < end; i += 1) {
    const c = pattern[i];
    if (c === "\\") {
      i += 1;
    } else if (c === "{") {
      depth += 1;
    } else if (c === "}") {
      if (depth === 0) return commas.length > 0 ? { close: i, commas } : null;
      depth -= 1;
    } else if (c === "," && depth === 0) {
      commas.push(i);
    }
  }
  return null;
}

function parseRange(pattern: string, start: number, end: number): Ast[] {
  const out: Ast[] = [];
  let i = start;
  while (i < end) {
    const c = pattern[i];
    if (c === "\\" && i + 1 < end) {
      const escaped = pattern[i + 1];
      out.push({ kind: "char", test: (x) => x === escaped });
      i += 2;
    } else if (c === "?") {
      out.push({ kind: "char", test: notSlash });
      i += 1;
    } else if (c === "*") {
      let runEnd = i;
      while (runEnd < end && pattern[runEnd] === "*") runEnd += 1;
      const segmentStart = i === 0 || pattern[i - 1] === "/";
      const segmentEnd = runEnd === pattern.length || pattern[runEnd] === "/";
      if (runEnd - i >= 2 && segmentStart && segmentEnd) {
        if (runEnd < end && pattern[runEnd] === "/") {
          out.push({ kind: "globstarDir" });
          i = runEnd + 1;
        } else {
          out.push({ kind: "globstar" });
          i = runEnd;
        }
      } else {
        out.push({ kind: "star" });
        i = runEnd;
      }
    } else if (c === "[") {
      const close = findClassEnd(pattern, i, end);
      if (close === -1) {
        out.push({ kind: "char", test: (x) => x === "[" });
        i += 1;
      } else {
        out.push({ kind: "char", test: parseClass(pattern, i, close) });
        i = close + 1;
      }
    } else if (c === "{") {
      const brace = scanBrace(pattern, i, end);
      if (!brace) {
        out.push({ kind: "char", test: (x) => x === "{" });
        i += 1;
      } else {
        const bounds = [i, ...brace.commas, brace.close];
        const options: Ast[][] = [];
        for (let b = 0; b < bounds.length - 1; b += 1) {
          options.push(parseRange(pattern, bounds[b] + 1, bounds[b + 1]));
        }
        out.push({ kind: "alt", options });
        i = brace.close + 1;
      }
    } else {
      out.push({ kind: "char", test: (x) => x === c });
      i += 1;
    }
  }
  return out;
}

function buildNfa(ast: Ast[]): { states: State[]; start: number } {
  const states: State[] = [{ kind: "match" }];
  const push = (state: State) => states.push(state) - 1;

  const loop = (test: (c: string) => boolean, exit: number) => {
    const split = push({ kind: "split", next: -1, alt: exit });
    const body = push({ kind: "char", test, next: split });
    (states[split] as { next: number }).next = body;
    return split;
  };

  const compileSeq = (seq: Ast[], next: number): number => {
    for (let k = seq.length - 1; k >= 0; k -= 1) next = compileNode(seq[k], next);
    return next;
  };

  const compileNode = (node: Ast, next: number): number => {
    switch (node.kind) {
      case "char":
        return push({ kind: "char", test: node.test, next });
      case "star":
        return loop(notSlash, next);
      case "globstar":
        return loop(anyChar, next);
      case "globstarDir": {
        const slash = push({ kind: "char", test: (x) => x === "/", next });
        return push({ kind: "split", next: loop(anyChar, slash), alt: next });
      }
      case "alt": {
        let start = compileSeq(node.options[node.options.length - 1], next);
        for (let k = node.options.length - 2; k >= 0; k -= 1) {
          start = push({ kind: "split", next: compileSeq(node.options[k], next), alt: start });
        }
        return start;
      }
    }
  };

  return { states, start: compileSeq(ast, 0) };
}

export function compileGlob(pattern: string, budget: GlobBudget): (input: string) => boolean {
  budget.remaining -= pattern.length + 1;
  if (pattern.length > MAX_PATTERN_LENGTH || pattern.startsWith("#") || budget.remaining <= 0) return () => false;

  let bangs = 0;
  while (pattern[bangs] === "!") bangs += 1;
  const negate = bangs % 2 === 1;
  const body = pattern.slice(bangs);
  const { states, start } = buildNfa(parseRange(body, 0, body.length));

  const seen = new Uint32Array(states.length);
  let generation = 0;

  const closure = (from: number[]): number[] => {
    generation += 1;
    const out: number[] = [];
    const stack = from.slice();
    while (stack.length > 0) {
      budget.remaining -= 1;
      const index = stack.pop() as number;
      if (seen[index] === generation) continue;
      seen[index] = generation;
      const state = states[index];
      if (state.kind === "split") {
        stack.push(state.alt, state.next);
      } else {
        out.push(index);
      }
    }
    return out;
  };

  const matches = (input: string): boolean | null => {
    let current = closure([start]);
    for (const c of input) {
      if (current.length === 0) return false;
      budget.remaining -= current.length;
      if (budget.remaining <= 0) return null;
      const next: number[] = [];
      for (const index of current) {
        const state = states[index];
        if (state.kind === "char" && state.test(c)) next.push(state.next);
      }
      current = closure(next);
    }
    return current.some((index) => states[index].kind === "match");
  };

  return (input) => {
    budget.remaining -= 1;
    if (budget.remaining <= 0) return false;
    const result = matches(input);
    return result === null ? false : result !== negate;
  };
}
