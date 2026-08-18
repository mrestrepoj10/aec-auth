import { compileDeclarativeMatchers, type DeepsecPlugin } from "deepsec/config";

const specs = [
  {
    "version": 1,
    "slug": "nextjs-og-image-renderer",
    "description": "Identifies the documentation site's Next.js Open Graph image renderer through its concrete ImageResponse construction.",
    "noiseTier": "precise",
    "filePatterns": [
      "apps/docs/src/app/og/og-image.tsx"
    ],
    "patterns": [
      {
        "source": "^\\s*return\\s+new\\s+ImageResponse\\s*\\(",
        "flags": "m",
        "label": "Next.js ImageResponse construction"
      }
    ],
    "examples": [
      "  return new ImageResponse("
    ],
    "closesSurfaceIds": [
      "documentation-http"
    ]
  },
  {
    "version": 1,
    "slug": "aps-two-legged-token-entrypoint",
    "description": "Identifies the executable APS two-legged OAuth smoke test through its top-level app-subject token acquisition.",
    "noiseTier": "precise",
    "filePatterns": [
      "examples/aps-2legged.mjs"
    ],
    "patterns": [
      {
        "source": "^const\\s+token\\s*=\\s*await\\s+tokens\\.getToken\\s*\\(\\s*\\{$",
        "flags": "m",
        "label": "Top-level APS app token acquisition"
      }
    ],
    "examples": [
      "const token = await tokens.getToken({"
    ],
    "closesSurfaceIds": [
      "oauth-example-cli"
    ]
  }
];

export const generatedMatchersPlugin: DeepsecPlugin = {
  name: "deepsec-generated-matchers",
  matchers: compileDeclarativeMatchers(specs),
};
