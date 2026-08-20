export type NavItem = {
  name: string
  href: string
}

export const allDocsPages: NavItem[] = [
  { name: 'Overview', href: '/' },
  { name: 'Quickstart', href: '/quickstart' },
  { name: 'Existing Projects', href: '/existing-projects' },
  { name: 'Three-Legged Auth', href: '/three-legged' },
  { name: 'Better Auth', href: '/better-auth' },
  { name: 'Production', href: '/production' },
  { name: 'Testing', href: '/testing' },
  { name: 'Official APS SDK', href: '/aps-sdk' },
  { name: 'The 15-Day Problem', href: '/grants' },
  { name: 'Reference', href: '/reference' },
  { name: 'Changelog', href: '/changelog' },
]
