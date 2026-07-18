# Preview spec

- Dimensions: `1600x900`
- Format: static PNG terminal card
- Background: page `#0b1020`, panel `#111827`, header `#0f172a`
- Typography: monospace (`Menlo` or fallback)
- Padding: 72px outer, 48px inner
- Chrome: rounded panel with three header dots
- Prompt color: `#60a5fa`
- Body color: `#e5e7eb`
- Accent colors: green `#34d399`, yellow `#fbbf24`, red `#f87171`
- Command shown: `agent-warden --scope examples/scope.low-disruption.yaml --agent-pid 12345 --poll 0.5`
- Exact output shown: the contents of `assets/preview-source.txt`
- Rule: use real CLI output only, no mock UI, no GIFs, no stock art
