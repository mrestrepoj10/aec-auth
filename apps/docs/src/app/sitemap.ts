import type { MetadataRoute } from 'next'
import { allDocsPages } from '@/lib/docs-navigation'

const baseUrl = 'https://aec-auth.dev'

export default function sitemap(): MetadataRoute.Sitemap {
  return allDocsPages.map((page) => ({
    url: `${baseUrl}${page.href}`,
    lastModified: new Date(),
  }))
}
