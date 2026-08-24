import { describe, expect, it, vi } from 'vitest'
import { apsPaginate, createApsClient } from '../src/aps'
import { apsFixtures, mockApsFetch, mockTokenSource } from '../src/mock'

/** A stub client whose `request` serves the given pages in order. */
function stubClient(pages: unknown[]) {
  const request = vi.fn(async () => pages.shift())
  return { client: { request } as never, request }
}

async function drain<T>(iterator: AsyncGenerator<T, void, undefined>): Promise<T[]> {
  const items: T[] = []
  for await (const item of iterator) items.push(item)
  return items
}

describe('apsPaginate', () => {
  it('follows JSON:API links.next.href, reduced to path + query', async () => {
    const { client, request } = stubClient([
      {
        data: [1, 2],
        links: {
          next: {
            href: 'https://developer.api.autodesk.com/data/v1/projects/p/folders/f/contents?page%5Bnumber%5D=1',
          },
        },
      },
      { data: [3], links: {} },
    ])

    const items = await drain(apsPaginate<number>(client, '/data/v1/projects/p/folders/f/contents'))

    expect(items).toEqual([1, 2, 3])
    expect(request).toHaveBeenCalledTimes(2)
    expect(request).toHaveBeenNthCalledWith(1, '/data/v1/projects/p/folders/f/contents', undefined)
    expect(request).toHaveBeenNthCalledWith(
      2,
      '/data/v1/projects/p/folders/f/contents?page%5Bnumber%5D=1',
      undefined,
    )
  })

  it('follows ACC pagination.nextUrl in absolute and root-relative forms', async () => {
    const { client, request } = stubClient([
      {
        results: ['a'],
        pagination: {
          nextUrl: 'https://developer.api.autodesk.com/construction/issues/v1/issues?offset=2',
        },
      },
      { results: ['b'], pagination: { nextUrl: '/construction/issues/v1/issues?offset=4' } },
      { results: ['c'], pagination: {} },
    ])

    const items = await drain(apsPaginate<string>(client, '/construction/issues/v1/issues'))

    expect(items).toEqual(['a', 'b', 'c'])
    expect(request).toHaveBeenNthCalledWith(2, '/construction/issues/v1/issues?offset=2', undefined)
    expect(request).toHaveBeenNthCalledWith(3, '/construction/issues/v1/issues?offset=4', undefined)
  })

  it('synthesizes offset pages from limit/offset/totalResults', async () => {
    const { client, request } = stubClient([
      { results: [1, 2], pagination: { limit: 2, offset: 0, totalResults: 5 } },
      { results: [3, 4], pagination: { limit: 2, offset: 2, totalResults: 5 } },
      { results: [5], pagination: { limit: 2, offset: 4, totalResults: 5 } },
    ])

    const items = await drain(apsPaginate<number>(client, '/construction/issues/v1/issues'))

    expect(items).toEqual([1, 2, 3, 4, 5])
    expect(request).toHaveBeenCalledTimes(3)
    expect(request).toHaveBeenNthCalledWith(
      2,
      '/construction/issues/v1/issues?offset=2&limit=2',
      undefined,
    )
    expect(request).toHaveBeenNthCalledWith(
      3,
      '/construction/issues/v1/issues?offset=4&limit=2',
      undefined,
    )
  })

  it('follows a webhooks-style string links.next as a path', async () => {
    const { client, request } = stubClient([
      { data: ['h1'], links: { next: '/webhooks/v1/app/hooks?pageState=abc' } },
      { data: ['h2'] },
    ])

    const items = await drain(apsPaginate<string>(client, '/webhooks/v1/app/hooks'))

    expect(items).toEqual(['h1', 'h2'])
    expect(request).toHaveBeenNthCalledWith(2, '/webhooks/v1/app/hooks?pageState=abc', undefined)
  })

  it('terminates when the next path repeats the current one', async () => {
    const { client, request } = stubClient([{ data: ['only'], links: { next: '/loop' } }])

    const items = await drain(apsPaginate<string>(client, '/loop'))

    expect(items).toEqual(['only'])
    expect(request).toHaveBeenCalledTimes(1)
  })

  it('yields nothing for empty and bare pages without extra requests', async () => {
    const empty = stubClient([{ data: [] }])
    expect(await drain(apsPaginate(empty.client, '/x'))).toEqual([])
    expect(empty.request).toHaveBeenCalledTimes(1)

    const bare = stubClient([{}])
    expect(await drain(apsPaginate(bare.client, '/x'))).toEqual([])
    expect(bare.request).toHaveBeenCalledTimes(1)
  })

  it('composes with createApsClient and mockApsFetch', async () => {
    const client = createApsClient({
      tokens: mockTokenSource(),
      subject: { type: 'app' },
      fetch: mockApsFetch(),
    })

    const hubs = await drain(apsPaginate(client, '/project/v1/hubs'))

    expect(hubs).toEqual(apsFixtures.hubs)
  })
})
