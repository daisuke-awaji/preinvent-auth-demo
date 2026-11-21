const toArray = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

const wildcardToRegExp = (pattern, ignoreCase = false) =>
  new RegExp(
    `^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`,
    ignoreCase ? 'i' : '',
  );

const BASE_OPERATORS = {
  StringEquals: { negated: false, test: (a, b) => a === b },
  StringNotEquals: { negated: true, test: (a, b) => a === b },
  StringEqualsIgnoreCase: { negated: false, test: (a, b) => a.toLowerCase() === b.toLowerCase() },
  StringNotEqualsIgnoreCase: { negated: true, test: (a, b) => a.toLowerCase() === b.toLowerCase() },
  StringLike: { negated: false, test: (a, b) => wildcardToRegExp(b).test(a) },
  StringNotLike: { negated: true, test: (a, b) => wildcardToRegExp(b).test(a) },
};

function parseOperator(raw) {
  let rest = raw;
  let setOp = null;
  const m = /^(ForAnyValue|ForAllValues):(.+)$/.exec(rest);
  if (m) {
    setOp = m[1];
    rest = m[2];
  }
  let ifExists = false;
  if (rest.endsWith('IfExists')) {
    ifExists = true;
    rest = rest.slice(0, -'IfExists'.length);
  }
  return { setOp, base: rest, ifExists };
}

function matchesSingle(op, ctxValue, policyValues) {
  const anyEqual = policyValues.some((pv) => op.test(String(ctxValue), String(pv)));
  return op.negated ? !anyEqual : anyEqual;
}

export function evaluateCondition(rawOperator, key, policyValue, context) {
  const values = toArray(policyValue);
  const ctx = context[key];
  const absent = ctx === undefined || (Array.isArray(ctx) && ctx.length === 0);
  const { setOp, base, ifExists } = parseOperator(rawOperator);

  if (base === 'Null') {
    const wantAbsent = String(values[0]).toLowerCase() === 'true';
    return { result: wantAbsent === absent, note: `${key} は${absent ? '存在しない' : '存在する'}` };
  }

  const op = BASE_OPERATORS[base];
  if (!op) return { result: false, note: `未対応の演算子 ${rawOperator}（模擬評価では false 扱い）` };

  if (setOp === 'ForAnyValue') {
    if (absent) return { result: false, note: `${key} が無いので ForAnyValue は false` };
    const result = toArray(ctx).some((c) => matchesSingle(op, c, values));
    return { result, note: `${key}=${JSON.stringify(ctx)}` };
  }
  if (setOp === 'ForAllValues') {
    if (absent) return { result: true, note: `${key} が無いので ForAllValues は true` };
    const result = toArray(ctx).every((c) => matchesSingle(op, c, values));
    return { result, note: `${key}=${JSON.stringify(ctx)}` };
  }

  if (absent) {
    if (ifExists) return { result: true, note: `${key} が無いので IfExists は true` };
    return { result: op.negated, note: `${key} が無いので ${op.negated ? '否定演算子は true' : 'false'}` };
  }
  const ctxValues = toArray(ctx);
  const result = op.negated
    ? ctxValues.every((c) => matchesSingle(op, c, values))
    : ctxValues.some((c) => matchesSingle(op, c, values));
  return { result, note: `${key}=${JSON.stringify(ctx)}` };
}

function principalMatches(principal) {
  if (principal === '*') return true;
  if (principal && typeof principal === 'object') return toArray(principal.AWS).includes('*');
  return false;
}

const patternMatches = (patterns, value) => toArray(patterns).some((p) => wildcardToRegExp(p, true).test(value));

export function evaluatePolicy(policy, { action, resource, context }) {
  const statements = toArray(policy?.Statement);
  const details = statements.map((st, index) => {
    const sid = st.Sid ?? `Statement[${index}]`;
    const reasons = [];
    if (!principalMatches(st.Principal)) {
      reasons.push('Principal が "*" ではない（JWT 認証の呼び出しは匿名プリンシパル扱い）');
      return { sid, effect: st.Effect, matched: false, reasons };
    }
    if (st.Action !== undefined && !patternMatches(st.Action, action)) {
      reasons.push(`Action が ${action} に一致しない`);
      return { sid, effect: st.Effect, matched: false, reasons };
    }
    if (st.Resource !== undefined && !patternMatches(st.Resource, resource)) {
      reasons.push('Resource が一致しない');
      return { sid, effect: st.Effect, matched: false, reasons };
    }
    let matched = true;
    for (const [operator, block] of Object.entries(st.Condition ?? {})) {
      for (const [key, value] of Object.entries(block)) {
        const { result, note } = evaluateCondition(operator, key, value, context);
        reasons.push(`${operator} ${key} → ${result}（${note}）`);
        if (!result) matched = false;
      }
    }
    if (!st.Condition) reasons.push('条件なし → 常に一致');
    return { sid, effect: st.Effect, matched, reasons };
  });

  const deny = details.find((d) => d.matched && d.effect === 'Deny');
  const allow = details.find((d) => d.matched && d.effect === 'Allow');
  const decision = deny ? 'Deny' : allow ? 'Allow' : 'ImplicitDeny';
  return { decision, decidedBy: deny?.sid ?? allow?.sid ?? null, statements: details };
}

export function jwtClaimsToContext(claims) {
  const ctx = {};
  const prefix = 'bedrock-agentcore:InboundJwtClaim/';
  for (const k of ['iss', 'sub', 'client_id']) if (claims[k] !== undefined) ctx[prefix + k] = String(claims[k]);
  if (claims.aud !== undefined) ctx[`${prefix}aud`] = toArray(claims.aud).map(String);
  if (typeof claims.scope === 'string') ctx[`${prefix}scope`] = claims.scope.split(' ').filter(Boolean);
  return ctx;
}
