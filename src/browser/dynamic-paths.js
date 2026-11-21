export const isDynamicPath = (p) => p === '/callback' || /^\/(api|mock|backend|cimd)\//.test(p);
