// Executable ESM integration tests; fake only the host SDK and React hooks.
// The plugin's request, route guards, mutations, copy and component functions are real.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const source = await readFile(new URL('../../desktop/plugin.js', import.meta.url), 'utf8')
const uri = (code) => 'data:text/javascript;base64,' + Buffer.from(code).toString('base64')
const env = (globalThis.__securityTest = {
  calls: [],
  events: new Map(),
  registrations: [],
  invalidations: [],
  queryOptions: [],
  draft: null,
  draftReady: true,
  profile: 'remote-profile',
  fixtures: {
    '/summary': { profile: 'remote-profile', scans: 2, findings: 1 },
    '/scans': {
      items: [
        { scanId: 'scan_test', mode: 'deep', status: 'interrupted', target: { root: '/remote/project' } }
      ],
      total: 1
    },
    '/findings': {
      items: [
        {
          findingId: 'hsf_test',
          title: 'A member reads another tenant invoice',
          evidenceState: 'source_supported',
          severity: { level: 'high' }
        }
      ],
      total: 1
    },
    '/scans/scan_test': {
      scanId: 'scan_test',
      status: 'awaiting_analysis',
      target: { root: '/remote/project', snapshotDigest: 'sha256:fixture' }
    },
    '/findings/hsf_test': {
      findingId: 'hsf_test',
      scan: { scanId: 'scan_test', target: { root: '/remote/project' } },
      triage: { state: 'open' }
    },
    '/findings/hsf_test/patch': { findingId: 'hsf_test', readOnly: true, content: 'Add an ownership check.' }
  }
})
const jsxModule = uri(
  'export function jsx(type,props,key){ return {type,props:props||{},key} }; export const jsxs=jsx;'
)
const reactModule = uri(
  'export const useState = v => [globalThis.__securityTest.states?.length ? globalThis.__securityTest.states.shift() : typeof v === "function" ? v() : v, () => {}]; export const useEffect = () => {}; export const useRef=v=>({current:v});'
)
const sdkModule = uri(`
const e=globalThis.__securityTest;
export const Button='button', Input='input', Textarea='textarea', Dialog='dialog', DialogContent='div', DialogHeader='header', DialogTitle='h2', DialogDescription='p', DialogFooter='footer';
export const ROUTES_AREA='routes', SIDEBAR_NAV_AREA='sidebar.nav', PALETTE_AREA='palette';
export const host={state:{profile:{get:()=>e.profile},connectionId:{get:()=>e.connectionId||null},focusedSessionOwner:{get:()=>e.owner||null},focusedStoredSessionId:{get:()=>null},activeSessionId:{get:()=>null}},notify:v=>e.notice=v,navigate:p=>e.navigation=p,openSession:async id=>e.session=id,composer:{insertText:async (id,text,options)=>{e.draft={id,text,options};return e.draftReady}}};
export const queryClient={invalidateQueries:async v=>e.invalidations.push(v),removeQueries:v=>e.removed=v};
export const useValue=atom=>atom.get();
export const useQuery=options=>{e.queryOptions.push(options);return {data:options.enabled === false ? undefined : e.fixtures[options.queryKey[2]+'#'+(new URLSearchParams(options.queryKey[3]).get('section')||'')] || e.fixtures[options.queryKey[2]],isLoading:false,refetch:()=>options.queryFn()}};
export const useMutation=options=>({mutate:options.mutationFn,isPending:false});
`)
const moduleCode = source
  .replaceAll("'@hermes/plugin-sdk'", JSON.stringify(sdkModule))
  .replaceAll("'react/jsx-runtime'", JSON.stringify(jsxModule))
  .replaceAll("'react'", JSON.stringify(reactModule))
const plugin = await import(uri(moduleCode))
const context = {
  registerMany: (rows) => env.registrations.push(...rows),
  onEvent: (name, fn) => env.events.set(name, fn),
  onDispose: (fn) => {
    env.dispose = fn
  },
  rest: async (path, options) => {
    env.calls.push({ path, options })
    if (env.error) throw env.error
    if (env.response !== undefined) return env.response
    if (options.method === 'POST') {
      if (path.endsWith('/cancel')) env.fixtures['/scans/scan_test'].status = 'canceled'
      if (path.endsWith('/resume')) env.fixtures['/scans/scan_test'].status = 'awaiting_analysis'
      if (path.endsWith('/triage')) env.fixtures['/findings/hsf_test'].triage = { ...options.body }
      return structuredClone(env.fixtures[path.replace(/\/(cancel|resume|triage)$/, '')])
    }
    return structuredClone(env.fixtures[path.split('?')[0]] || { items: [], total: 0 })
  }
}
plugin.default.register(context)
function render(node) {
  if (Array.isArray(node)) return node.map(render).join(' ')
  if (node === null || node === undefined || typeof node === 'boolean') return ''
  if (typeof node !== 'object') return String(node)
  if (typeof node.type === 'function') return render(node.type(node.props))
  return render(node.props?.children)
}

test('registers exactly one route, sidebar and palette entry, opt-in', () => {
  assert.equal(plugin.default.defaultEnabled, false)
  assert.equal(env.registrations.length, 3)
  assert.equal(env.registrations.find((r) => r.area === 'routes').data.path, '/security')
  env.registrations.find((r) => r.area === 'palette').data.run()
  assert.equal(env.navigation, '/security')
})
test('state labels preserve uncertainty and NOT RUN', () => {
  assert.deepEqual(Object.values(plugin.EVIDENCE_LABELS), [
    'Needs review',
    'Supported by code',
    'Confirmed by test',
    'Not an issue',
    "Couldn't confirm"
  ])
  assert.equal(plugin.label('NOT_RUN'), 'NOT RUN')
  assert.equal(plugin.label(null), 'Unknown')
})
test('query keys partition profiles, filters and pagination', () => {
  assert.notDeepEqual(plugin.queryKey('a', '/findings'), plugin.queryKey('b', '/findings'))
  assert.deepEqual(
    plugin.queryKey('a', '/findings', { q: 'foo', offset: 0 }),
    plugin.queryKey('a', '/findings', { offset: 0, q: 'foo' })
  )
  const filters = { q: 'a&b / exact', chained: false, limit: 40, offset: 0, severity: '', repo: undefined }
  const query = new URLSearchParams(plugin.filtersToQuery(filters))
  assert.equal(query.get('q'), filters.q)
  assert.equal(query.get('chained'), 'false')
  assert.equal(query.get('offset'), '0')
  assert.equal(query.has('repo'), false)
})
test('only contract paths pass; traversal, external and authority routes fail', () => {
  for (const path of [
    '/summary',
    '/scans?limit=40',
    '/scans/scan_test',
    '/scans/scan_test/cancel',
    '/scans/scan_test/resume',
    '/scans/scan_test/activity',
    '/scans/scan_test/coverage',
    '/findings',
    '/findings/hsf_test',
    '/findings/hsf_test/triage',
    '/findings/hsf_test/patch',
    '/repositories',
    '/exports/scan_test/md',
    '/exports/scan_test/sarif',
    '/exports/scan_test/json',
    '/exports/scan_test/csv'
  ])
    assert.equal(plugin.assertBackendPath(path), path)
  for (const path of [
    '/health',
    '/authorize',
    '/scans/../summary',
    '/scans/%2e%2e',
    'https://elsewhere/api',
    '/findings/id/apply',
    '/exports/id/pdf'
  ])
    assert.throws(() => plugin.assertBackendPath(path))
})
test('scans and findings read from the mocked scoped backend', async () => {
  assert.equal((await plugin.request('/scans?q=remote&offset=0')).items[0].status, 'interrupted')
  assert.equal((await plugin.request('/findings')).items[0].evidenceState, 'source_supported')
  assert.equal(env.calls.at(-1).options.timeoutMs, 15000)
})
test('stop and resume use actual readback, then invalidate queries', async () => {
  const result = await plugin.change('/scans/scan_test/cancel', {}, { status: 'canceled' })
  assert.equal(result.status, 'canceled')
  assert.equal((await plugin.request('/scans/scan_test')).status, 'canceled')
  assert.equal(
    (await plugin.change('/scans/scan_test/resume', {}, { status: ['running', 'awaiting_analysis'] })).status,
    'awaiting_analysis'
  )
  assert.deepEqual(env.invalidations.at(-1), { queryKey: ['hermes-security'] })
})
test('triage readback confirms saved state and note; patch remains GET only', async () => {
  const saved = await plugin.change(
    '/findings/hsf_test/triage',
    { state: 'accepted_risk', note: 'Owner accepted' },
    { state: 'accepted_risk' }
  )
  assert.equal(saved.triage.note, 'Owner accepted')
  assert.equal((await plugin.request('/findings/hsf_test')).triage.state, 'accepted_risk')
  assert.equal((await plugin.request('/findings/hsf_test/patch')).readOnly, true)
  assert.equal(env.calls.at(-1).options.method, undefined)
})
test('missing, wrong or error readbacks do not claim success', async () => {
  const before = env.invalidations.length
  for (const response of [
    { ok: true },
    { status: 'running' },
    { scanId: 'scan_other', status: 'canceled' },
    { error: { code: 'conflict', message: 'Scan is sealed; use a new scan.' } }
  ]) {
    env.response = response
    await assert.rejects(plugin.change('/scans/scan_test/cancel', {}, { status: 'canceled' }))
  }
  delete env.response
  assert.equal(env.invalidations.length, before)
  assert.throws(() => plugin.readback(null), /did not return saved state/)
})
test('backend error message is visible, including JSON error envelopes', async () => {
  env.error = new Error(
    JSON.stringify({ error: { code: 'conflict', message: 'Snapshot changed. Start a new scan.' } })
  )
  await assert.rejects(plugin.request('/scans/scan_test'), /Snapshot changed. Start a new scan./)
  delete env.error
})
test('draft preserves backend paths and options, never submits or starts scan', async () => {
  const before = env.calls.length
  const options = {
    path: '/remote/path with spaces',
    mode: 'diff',
    safetyLevel: 'static',
    context: 'User context',
    scope: ['src/**']
  }
  await plugin.putDraft(plugin.scanDraft(options))
  assert.match(env.draft.text, /hermes-security:security-audit/)
  assert.match(env.draft.text, /\/remote\/path with spaces/)
  assert.equal(env.draft.id, 'new')
  assert.equal(env.calls.length, before)
  env.draftReady = false
  await assert.rejects(plugin.putDraft('retry'), /No scan was started/)
  env.draftReady = true
})
test('high confidence without excerpt has warning and proof-gap explanation', () => {
  const output = render(
    plugin.Evidence({ finding: { confidence: { level: 'high' }, validation: { status: 'NOT_RUN' } } })
  )
  assert.match(output, /Evidence warning/)
  assert.match(output, /No proof-gap explanation recorded/)
  assert.match(output, /NOT RUN/)
})
test('secret evidence renders only type and fingerprint, never raw excerpt', () => {
  const output = render(
    plugin.Evidence({
      finding: {
        secret: { type: 'test-key', fingerprint: 'sha256:fixture', value: 'must-not-display' },
        codeEvidence: [{ code: 'must-not-display' }]
      }
    })
  )
  assert.match(output, /test-key/)
  assert.match(output, /sha256:fixture/)
  assert.doesNotMatch(output, /must-not-display/)
})
test('every chain edge renders evidence, assumptions and defeating controls', () => {
  const edges = [1, 2].map((n) => ({
    from: `from-${n}`,
    to: `to-${n}`,
    evidenceRefs: [`evidence-${n}`],
    assumptions: [`required-${n}`],
    counterEvidence: [`defeating-${n}`],
    state: 'supported'
  }))
  const output = render(
    plugin.Chains({
      chains: [{ chainId: 'chain-1', edges, conditional: true, disposition: 'candidate_chain' }]
    })
  )
  for (const n of [1, 2])
    for (const prefix of ['from', 'to', 'evidence', 'required', 'defeating'])
      assert.ok(output.includes(`${prefix}-${n}`))
  assert.match(output, /Conditional/)
})
test('coverage keeps missing work and zero-finding uncertainty visible', () => {
  const output = render(
    plugin.Coverage({
      data: {
        completeness: 'partial',
        files: { reviewed: 1, total: 3 },
        gaps: ['Worker missing', 'Detector failed']
      }
    })
  )
  assert.match(output, /partial/)
  assert.match(output, /1 of 3/)
  assert.match(output, /Worker missing/)
  assert.match(output, /Zero findings does not establish/)
})
test('progress never invents completion and mounts aria-live stepper', () => {
  const node = plugin.Progress({ scan: {} })
  assert.match(render(node), /Inventory — Not recorded/)
  assert.match(render(node), /Finalization — Not recorded/)
  assert.equal(node.props.children[0].props['aria-live'], 'polite')
})
test('full page evaluates through SDK React shim and uses six-second queries', () => {
  const output = render(plugin.SecurityPage())
  assert.match(output, /Security/)
  assert.match(output, /remote-profile/)
  assert.match(output, /\/remote\/project/)
  for (const q of env.queryOptions) assert.equal(q.refetchInterval, 6000)
  assert.ok(env.queryOptions.some((q) => q.queryKey[2] === '/summary'))
})
test('legacy store projections normalize metadata without rewriting evidence', async () => {
  env.response = {
    items: [
      {
        scan_id: 'scan_exact',
        finding_id: 'hsf_exact',
        evidence_state: 'source_supported',
        created_at: '2026-01-01T00:00:00Z',
        last_scan_id: 'scan_latest',
        coverage_completeness: 'partial',
        codeEvidence: [{ code: 'scan_id must remain exact' }]
      }
    ]
  }
  const row = (await plugin.request('/scans')).items[0]
  assert.equal(row.scanId, 'scan_exact')
  assert.equal(row.findingId, 'hsf_exact')
  assert.equal(row.evidenceState, 'source_supported')
  assert.equal(row.latestScanId, 'scan_latest')
  assert.equal(row.coverageCompleteness, 'partial')
  assert.equal(row.codeEvidence[0].code, 'scan_id must remain exact')
  delete env.response
})
test('finding chains exclude unrelated scan chains and retain broken edges', () => {
  const result = plugin.relevantChains(
    {
      chains: [{ findingIds: ['a', 'b'] }, { findingIds: ['c'] }],
      broken: [{ edge: { from: 'b', to: 'z' } }]
    },
    'b'
  )
  assert.equal(result.chains.length, 1)
  assert.equal(result.broken.length, 1)
})
test('completed scan uses sealed manifest counts beside coverage', () => {
  env.fixtures['/scans/scan_done'] = {
    scanId: 'scan_done',
    status: 'completed',
    sealedAt: '2026-01-01T00:00:00Z',
    target: { root: '/remote/done' }
  }
  env.fixtures['/scans/scan_done#manifest'] = {
    counts: { critical: 0, high: 2, medium: 1, low: 0, informational: 0, chains: 1 },
    runtime: { model: 'fixture-model', provider: 'fixture-provider', profile: 'remote-profile' }
  }
  env.fixtures['/scans/scan_done/coverage'] = { completeness: 'partial', gaps: ['Review worker missing'] }
  env.fixtures['/scans/scan_done#findings'] = { items: [], total: 0 }
  const output = render(plugin.ScanDetail({ id: 'scan_done', onBack() {}, onFinding() {} }))
  assert.match(output, /2 high/)
  assert.match(output, /1 chains/)
  assert.match(output, /Review worker missing/)
  assert.match(output, /fixture-model/)
})
test('all finding tabs and repository metadata render without missing SDK references', () => {
  env.fixtures['/findings/hsf_test'] = {
    ...env.fixtures['/findings/hsf_test'],
    title: 'Test finding',
    summary: 'Effect',
    rootCause: 'Missing guard',
    evidenceState: 'source_supported',
    confidence: { level: 'high' },
    validation: { status: 'NOT_RUN' }
  }
  for (const tab of ['Summary', 'Evidence', 'Chains', 'Patch']) {
    env.states = [tab, 'open', '']
    const output = render(plugin.FindingDetail({ id: 'hsf_test', onBack() {} }))
    assert.match(output, /Test finding/)
    if (tab === 'Summary') assert.match(output, /Missing guard/)
    if (tab === 'Evidence') assert.match(output, /NOT RUN/)
    if (tab === 'Patch') assert.match(output, /Add an ownership check/)
  }
  env.states = []
  env.fixtures['/repositories'] = {
    items: [
      plugin.normalizeResponse({
        root: '/remote/repo',
        last_scan_id: 'scan_done',
        snapshot_digest: 'sha256:exact',
        unresolved_count: 3,
        coverage_completeness: 'partial'
      })
    ],
    total: 1
  }
  const output = render(plugin.Repositories({ onScan() {} }))
  assert.match(output, /scan_done/)
  assert.match(output, /sha256:exact/)
  assert.match(output, /Unresolved findings: 3/)
})
test('page owner and queries distinguish same-named remote profiles', async () => {
  env.connectionId = 'remote-a'
  const before = plugin.SecurityPage()
  render(before)
  const staleQuery = env.queryOptions.at(-1)
  env.connectionId = 'remote-b'
  const after = plugin.SecurityPage()
  assert.notEqual(before.key, after.key)
  await assert.rejects(staleQuery.queryFn(), /Backend changed/)
  assert.notDeepEqual(
    plugin.queryKey('default', '/summary', {}, 'remote-a'),
    plugin.queryKey('default', '/summary', {}, 'remote-b')
  )
  env.connectionId = null
})
test('draft refuses a chat belonging to another backend and reports failure after navigation', async () => {
  env.owner = { profile: 'other', connectionId: 'remote' }
  await assert.rejects(plugin.putDraft('must not insert'), /this backend profile/)
  assert.equal(env.notice.kind, 'error')
  env.owner = null
})
test('all export formats render the SDK JSON-envelope content', async () => {
  for (const format of ['md', 'sarif', 'json', 'csv']) {
    const path = `/exports/scan_done/${format}`
    env.fixtures[path] = {
      content: `fixture-${format}`,
      contentType: 'text/plain',
      filename: `scan.${format}`
    }
    env.states = [format, true]
    assert.match(render(plugin.ExportPanel({ id: 'scan_done' })), new RegExp(`fixture-${format}`))
    assert.equal((await plugin.request(path)).filename, `scan.${format}`)
  }
  env.states = []
})
test('finding readback keeps the finding when it embeds scan metadata', () => {
  const row = {
    findingId: 'hsf_nested',
    triage: { state: 'closed' },
    scan: { scanId: 'scan_nested', target: { root: '/remote/nested' } }
  }
  assert.equal(plugin.readback(row).findingId, 'hsf_nested')
  assert.equal(plugin.findingData(row).scanId, 'scan_nested')
  assert.equal(plugin.findingData(row).target.root, '/remote/nested')
})
test('scan/finding events invalidate and unload removes cache', () => {
  for (const name of ['plugin.hermes-security.scan.updated', 'plugin.hermes-security.finding.updated']) {
    assert.ok(env.events.has(name))
    env.events.get(name)({ payload: {} })
    assert.deepEqual(env.invalidations.at(-1), { queryKey: ['hermes-security'] })
  }
  env.dispose()
  assert.deepEqual(env.removed, { queryKey: ['hermes-security'] })
})
