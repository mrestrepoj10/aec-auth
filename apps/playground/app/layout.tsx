import type { ReactNode } from 'react'

export const metadata = { title: 'aec-auth playground' }

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          fontFamily: 'ui-sans-serif, system-ui, sans-serif',
          margin: '0 auto',
          maxWidth: 780,
          padding: '48px 24px',
          background: '#f6f6f2',
          color: '#21262b',
        }}
      >
        {children}
      </body>
    </html>
  )
}
