// Expose private runtime seams only in the test's in-memory or temporary copy.
export function exposeRuntime(source, names) {
  return source.replace("return { createPlugin,", `return { ${names}, createPlugin,`) +
    `\nexport const { ${names} } = defaultRuntime;\n`
}
