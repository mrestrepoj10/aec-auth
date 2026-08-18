import { getPageTitle, renderOgImage } from './og-image'

export async function GET() {
  const title = getPageTitle('') ?? 'aec-auth'
  return renderOgImage(title)
}
