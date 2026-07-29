// Mirrors o1js's own .prettierrc.cjs, because o1js's community-package
// guidance requires that "code must be auto-formatted with prettier" using the
// project's configuration.
//
// Two options from upstream are deliberately NOT copied:
//
//   * the markdown override (printWidth 80, proseWrap 'always') — applying it
//     here would reflow this repo's entire README and CHANGELOG for no benefit,
//     producing a diff that buries real changes.
//   * the `prettier-plugin-organize-imports` plugin — it sorts TypeScript
//     imports and needs a devDependency. All JS here is CommonJS `require`
//     calls in two small wrapper scripts, so it has nothing to do.
//
// Only the Node wrapper and its smoke test are JS; the analyzer itself is
// Python and is formatted by ruff.
module.exports = {
  trailingComma: 'es5',
  tabWidth: 2,
  semi: true,
  singleQuote: true,
  printWidth: 100,
};
