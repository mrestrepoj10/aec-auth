export const PAGE_TITLES: Record<string, string> = {
  '': 'The Token Layer\nfor AEC APIs',
  quickstart: 'Quickstart',
  'three-legged': 'Three-Legged Auth',
  'better-auth': 'Better Auth',
  production: 'Production Storage',
  testing: 'Testing',
  'aps-sdk': 'Official APS SDK',
  grants: 'The 15-Day Problem',
  reference: 'Reference',
  changelog: 'Changelog',
}

export function getPageTitle(slug: string): string | null {
  return slug in PAGE_TITLES ? PAGE_TITLES[slug] : null
}
