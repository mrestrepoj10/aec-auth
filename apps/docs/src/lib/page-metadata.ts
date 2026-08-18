import type { Metadata } from 'next'
import { PAGE_TITLES } from './page-titles'

const DESCRIPTION =
  'The token layer for AEC APIs — Autodesk Platform Services and Procore. Rotation-safe refresh, pluggable backends, typed clients.'

export function pageMetadata(slug: string): Metadata {
  const title = PAGE_TITLES[slug]
  if (!title) return {}

  const displayTitle = title.replace(/\n/g, ' ')
  const fullTitle = `${displayTitle} | aec-auth`
  const ogImageUrl = slug ? `/og/${slug}` : '/og'

  return {
    title: displayTitle,
    openGraph: {
      type: 'website',
      locale: 'en_US',
      siteName: 'aec-auth',
      title: fullTitle,
      description: DESCRIPTION,
      images: [
        {
          url: ogImageUrl,
          width: 1200,
          height: 630,
          alt: `${displayTitle} - aec-auth`,
        },
      ],
    },
    twitter: {
      card: 'summary_large_image',
      title: fullTitle,
      description: DESCRIPTION,
      images: [ogImageUrl],
    },
  }
}
