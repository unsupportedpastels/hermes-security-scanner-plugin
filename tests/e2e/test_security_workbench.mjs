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
  'export const useState = v => [globalThis.__securityTest.states?.length ? globalThis.__securityTest.states.shift() : typeof v === "function" ? v() : v, value => {globalThis.__securityTest.stateWrites?.push(value)}]; export const useEffect = fn => {if(globalThis.__securityTest.effects)globalThis.__securityTest.effects.push(fn)}; export const useRef=v=>({current:v});'
)
const sdkModule = uri(`
const e=globalThis.__securityTest;
export const Button='button', Input='input', Textarea='textarea', Dialog='dialog', DialogContent='div', DialogHeader='header', DialogTitle='h2', DialogDescription='p', DialogFooter='footer';
export const ROUTES_AREA='routes', SIDEBAR_NAV_AREA='sidebar.nav', PALETTE_AREA='palette';
export const host={state:{profile:{get:()=>e.profile},connectionId:{get:()=>e.connectionId||null},focusedSessionOwner:{get:()=>e.owner||null},focusedStoredSessionId:{get:()=>null},activeSessionId:{get:()=>null}},notify:v=>e.notice=v,navigate:p=>e.navigation=p,openSession:async id=>e.session=id,request:async (method,params)=>{(e.rpc=e.rpc||[]).push([method,params]);if(e.noSessions)throw new Error('unsupported');if(e.rpcHandler)return e.rpcHandler(method,params);return method==='session.create'?{session_id:'rt_1',stored_session_id:'st_1'}:{}},onEvent:(type,fn)=>{e.gatewayListener=fn;return ()=>{}},composer:{insertText:async (id,text,options)=>{e.draft={id,text,options};return e.draftReady}}};
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
      if (path === '/scans') return { scanId: 'scan_new', status: 'awaiting_analysis', target: { root: options.body.path } }
      if (path.endsWith('/session')) return { scanId: path.split('/')[2], options: { session: options.body } }
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

test('validation controls explain tests and offer optional app testing on open scans', () => {
  const local = render(plugin.ValidationControls({ id: 'scan_test', scan: { safetyLevel: 'local-safe', status: 'awaiting_analysis' } }))
  assert.match(local, /runs small tests from this repo/)
  assert.match(local, /Allow testing this app/)
  assert.doesNotMatch(local, /paste/i)
  const staticView = render(plugin.ValidationControls({ id: 'scan_test', scan: { safetyLevel: 'static', status: 'awaiting_analysis' } }))
  assert.match(staticView, /Run tests to confirm findings/)
  assert.match(staticView, /Allow testing this app/)
  const sealed = render(plugin.ValidationControls({ id: 'scan_test', scan: { safetyLevel: 'local-safe', status: 'completed', sealedAt: 'x' } }))
  assert.doesNotMatch(sealed, /Allow testing this app/)
})

test('validation click cancellation sends nothing; accepted click sends exact scan confirmation', async () => {
  const before = env.calls.length
  globalThis.window = { confirm: () => false }
  assert.equal(await plugin.confirmValidation('scan_test', 'run-validation', { plans: [] }, 'Run?'), null)
  assert.equal(env.calls.length, before)
  window.confirm = () => true
  env.response = { scanId: 'scan_test', receipts: [] }
  await plugin.confirmValidation('scan_test', 'run-validation', { plans: [] }, 'Run?')
  assert.equal(env.calls.at(-1).path, '/scans/scan_test/run-validation')
  assert.deepEqual(env.calls.at(-1).options.body, { plans: [], confirm: 'scan_test' })
  delete env.response
  delete globalThis.window
})

function nodes(node) {
  if (Array.isArray(node)) return node.flatMap(nodes)
  if (!node || typeof node !== 'object') return []
  if (typeof node.type === 'function') return nodes(node.type(node.props))
  return [node, ...nodes(node.props?.children)]
}

test('start form matches the simple flow and launches the scan in a background chat', async () => {
  env.fixtures['/repositories'] = { items: [{ repoKey: 'r1', root: '/remote/repo' }], total: 1 }
  env.fixtures['/folders'] = { root: '/remote/repo', items: ['src', 'tests'] }
  const view = nodes(plugin.NewScan({ onClose() {} }))
  assert.deepEqual(view.filter((n) => n.type === 'button' && n.props['aria-pressed'] !== undefined).map((n) => n.props.children), ['Whole codebase', 'Only my changes'])
  assert.deepEqual(view.filter((n) => n.type === 'option').map((n) => n.props.children), ['repo', 'Other folder…', 'Entire codebase', 'src/', 'tests/'])
  const text = render(plugin.NewScan({ onClose() {} }))
  for (const gone of [/Worker/, /Budget/, /Detectors/, /revision/i, /safety/i]) assert.doesNotMatch(text, gone)
  for (const shown of [/Deep scan/, /Run tests to confirm findings/, /Additional context/, /Scan area/]) assert.match(text, shown)
  for (const [options, expected] of [
    [{ path: '/remote/repo', otherPath: '', changes: false, deep: false, tests: false, folder: '', context: '  ' }, { path: '/remote/repo', mode: 'standard' }],
    [{ path: '__other', otherPath: ' /other/app ', changes: false, deep: true, tests: true, folder: 'src', context: ' Billing app ' },
     { path: '/other/app', mode: 'deep', scope: ['src/**'], allow_tests: true, context: 'Billing app' }],
    [{ path: '/remote/repo', otherPath: '', changes: true, deep: true, tests: false, folder: 'src', context: '' }, { path: '/remote/repo', mode: 'diff' }]
  ]) {
    env.states = [options, null, false]
    env.rpc = []
    let started
    const start = nodes(plugin.NewScan({ onClose() {}, onStarted: (id) => { started = id } })).find((n) => n.type === 'button' && n.props.children === 'Start scan')
    assert.equal(start.props.disabled, false)
    await start.props.onClick()
    const create = env.calls.filter((c) => c.path === '/scans').at(-1)
    assert.deepEqual(create.options.body, expected)
    assert.equal(started, 'scan_new')
    assert.deepEqual(env.rpc.map(([m]) => m), ['session.create', 'prompt.submit'])
    assert.match(env.rpc[1][1].text, /scan_new/)
    assert.deepEqual(env.calls.at(-1).options.body, { sessionId: 'rt_1', storedSessionId: 'st_1' })
    delete env.states
  }
  env.noSessions = true
  env.states = [{ path: '/remote/repo', otherPath: '', changes: false, deep: false, tests: false, folder: '', context: '' }, null, false]
  await nodes(plugin.NewScan({})).find((n) => n.type === 'button' && n.props.children === 'Start scan').props.onClick()
  assert.match(env.draft.text, /hermes-security:security-audit.*scan_new/)
  delete env.noSessions
  delete env.states
})

test('app permission allow and stop buttons ask before sending requests', async () => {
  env.fixtures['/scans/scan_test/grants'] = { items: [{ grantId: 'grt_test', scanId: 'scan_test', origins: ['http://localhost:8000'], used: 0, maxRequests: 2, expiresAt: '2099-01-01T00:00:00Z' }] }
  globalThis.window = { confirm: () => false }
  for (const level of ['local-safe', 'active-authorized']) {
    env.states = [0, 'http://localhost:8000', null, false, null]
    const view = nodes(plugin.ValidationControls({ id: 'scan_test', scan: { safetyLevel: level, status: 'awaiting_analysis' } }))
    const buttons = view.filter((n) => n.type === 'button' && ['Allow testing this app', 'Stop'].includes(n.props.children))
    assert.equal(buttons.length, 2)
    for (const button of buttons) {
      const before = env.calls.length
      await button.props.onClick()
      assert.equal(env.calls.length, before)
      window.confirm = () => true
      env.response = { scanId: 'scan_test', grantId: 'grt_test', revoked: button.props.children === 'Stop' }
      await button.props.onClick()
      assert.ok(env.calls.slice(before).some((call) => call.options?.body?.confirm === 'scan_test'))
      window.confirm = () => false
      delete env.response
    }
    delete env.states
  }
  delete env.fixtures['/scans/scan_test/grants']
  delete globalThis.window
})

test('test results and app permission state use everyday language', () => {
  env.fixtures['/scans/scan_test#validations'] = { items: [{ candidateId: 'cand_test', receiptId: 'vrc_test', status: 'passed', outputExcerpt: 'Observed output', cleanup: { done: true } }], total: 1 }
  for (const [grant, shown] of [
    [{ expiresAt: '2099-01-01T00:00:00Z', used: 0, maxRequests: 2 }, true],
    [{ expiresAt: '2000-01-01T00:00:00Z', used: 0, maxRequests: 2 }, false],
    [{ expiresAt: '2099-01-01T00:00:00Z', used: 2, maxRequests: 2 }, false],
    [{ expiresAt: '2099-01-01T00:00:00Z', used: 0, maxRequests: 2, revoked: true }, false]
  ]) {
    env.fixtures['/scans/scan_test/grants'] = { items: [{ grantId: 'grt_test', origins: ['http://localhost:8000'], ...grant }] }
    const output = render(plugin.ValidationControls({ id: 'scan_test', scan: { safetyLevel: 'local-safe', status: 'awaiting_analysis' } }))
    assert.equal(output.includes('requests used'), shown)
    assert.match(output, /1 test results.*Confirmed by test.*Observed output/)
    assert.doesNotMatch(output.replace(/https?:\/\/[^\s,)]+/g, ''), /\b(grant|receipt|validation|probe|authorize|HTTP)\b/i)
  }
  delete env.fixtures['/scans/scan_test#validations']
  delete env.fixtures['/scans/scan_test/grants']
})

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
  assert.match(output, /High confidence was recorded without a code excerpt/)
  assert.match(output, /Not tested: supported by reading the code/)
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
test('long gap lists collapse behind a count but stay readable', () => {
  const gaps = Array.from({ length: 266 }, (_, i) => `Control ${i} deferred`)
  const output = render(plugin.Coverage({ data: { completeness: 'partial', files: { reviewed: 0, total: 1 }, gaps } }))
  assert.match(output, /266 coverage gaps recorded/)
  assert.match(output, /Control 265 deferred/)
})
test('progress never invents completion and mounts aria-live stepper', () => {
  const node = plugin.Progress({ scan: {} })
  assert.equal(node.props['aria-live'], 'polite')
  assert.ok(node.props.children.every((li) => li.props['data-state'] === 'pending'))
  assert.match(render(node), /Prepare.*Review.*Verify.*Report/)
  const live = plugin.Progress({ scan: { progress: { steps: [{ label: 'Preparing scan', state: 'done' }, { label: 'Building threat model', state: 'done' }, { label: 'Reviewing code', state: 'active' }] } } })
  assert.deepEqual(live.props.children.map((li) => li.props['data-state']), ['done', 'active', 'pending', 'pending'])
  assert.match(render(live), /Reviewing code/)
  const half = plugin.stages([{ label: 'Validating findings', state: 'done' }, { label: 'Tracing attack paths', state: 'pending' }])
  assert.equal(half[2].state, 'active')
  const unknown = plugin.stages([{ label: 'Something new', state: 'active' }])
  assert.deepEqual(unknown, [{ name: 'Something new', state: 'active' }])
})
test('full page evaluates through SDK React shim and uses six-second queries', () => {
  env.states = ['Scans', null, false, {}]
  const output = render(plugin.SecurityPage())
  delete env.states
  for (const tab of ['Scans', 'Findings', 'New scan']) assert.match(output, new RegExp(tab))
  assert.doesNotMatch(output, /Repositories/)
  assert.match(output, /project/)
  for (const q of env.queryOptions) assert.equal(q.refetchInterval, 6000)
  assert.ok(env.queryOptions.some((q) => q.queryKey[2] === '/scans'))
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
  assert.match(output, /2 high · 1 medium/)
  assert.match(output, /Deep scan|Scan/)
  assert.match(output, /Review worker missing/)
  assert.match(output, /fixture-model/)
  assert.match(output, /Run in chat/)
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
  env.states = ['', null]
  const output = render(plugin.FindingDetail({ id: 'hsf_test', onBack() {} }))
  assert.match(output, /Test finding/)
  assert.match(output, /Missing guard/)
  assert.match(output, /Not tested/)
  assert.match(output, /Add an ownership check/)
  assert.match(output, /Fix in chat/)
  env.states = []
  const page = render(plugin.BrowserView({ kind: 'Findings', selected: null, setSelected() {}, onFinding: {}, newScan: false, setNewScan() {} }))
  assert.match(page, /A member reads another tenant invoice/)
  assert.match(page, /high/)
  assert.match(page, /Any severity/)
  assert.ok(env.queryOptions.some((q) => q.queryKey[2] === '/findings' && new URLSearchParams(q.queryKey[3]).get('status') === 'open'))
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
test('every export format downloads the backend content with its filename', async () => {
  const saved = []
  globalThis.document = { createElement: () => ({ click() { saved.push([this.download, this.href]) } }) }
  for (const format of ['md', 'sarif', 'json', 'csv']) {
    env.fixtures[`/exports/scan_done/${format}`] = { content: `fixture-${format}`, contentType: 'text/plain', filename: `scan.${format}` }
    assert.equal(await plugin.downloadExport('scan_done', format), `scan.${format}`)
  }
  assert.deepEqual(saved.map(([name]) => name), ['scan.md', 'scan.sarif', 'scan.json', 'scan.csv'])
  assert.ok(saved.every(([, href]) => href.startsWith('blob:')))
  assert.match(render(plugin.ExportPanel({ id: 'scan_done' })), /Report \(Markdown\).*SARIF/)
  delete globalThis.document
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
test('finding editor restores the saved triage note on reopening', () => {
  env.fixtures['/findings/hsf_test'].triage = { state: 'accepted_risk', note: 'Preserve owner rationale' }
  env.effects = []
  env.stateWrites = []
  plugin.FindingDetail({ id: 'hsf_test', onBack() {} })
  env.effects.forEach(effect => effect())
  assert.ok(env.stateWrites.includes('Preserve owner rationale'))
  delete env.effects
  delete env.stateWrites
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

test('a paused open scan says why and continues in its own chat', async () => {
  plugin.default.register(context)   // the previous test unloads the plugin
  env.fixtures['/scans/scan_paused'] = {
    scanId: 'scan_paused', status: 'awaiting_analysis', reason: 'paused: needs attention',
    target: { root: '/remote/paused' }, options: { session: { sessionId: 'rt_1', storedSessionId: 'st_1' } }
  }
  env.fixtures['/scans/scan_paused#findings'] = { items: [], total: 0 }
  const output = render(plugin.ScanDetail({ id: 'scan_paused', onBack() {}, onFinding() {} }))
  assert.match(output, /Paused — needs attention/)
  assert.doesNotMatch(output, /Running/)
  const button = () => nodes(plugin.ScanDetail({ id: 'scan_paused', onBack() {}, onFinding() {} }))
    .find((n) => n.type === 'button' && n.props.children === 'Continue scan')
  env.rpc = []
  await button().props.onClick()
  assert.deepEqual(env.rpc, [['prompt.submit', { session_id: 'rt_1', text: plugin.continuePrompt('scan_paused') }]])
  assert.match(plugin.continuePrompt('scan_paused'), /^Continue security scan scan_paused\. Read security_scan_get section next/)
  // A chat the backend no longer holds is reopened from its saved id, then relinked.
  env.rpc = []
  env.rpcHandler = (method) => {
    if (method === 'prompt.submit' && env.rpc.length === 1) throw new Error('session not found')
    return method === 'session.resume' ? { session_id: 'rt_2' } : {}
  }
  await button().props.onClick()
  delete env.rpcHandler
  assert.deepEqual(env.rpc.map(([m, p]) => [m, p.session_id]), [['prompt.submit', 'rt_1'], ['session.resume', 'st_1'], ['prompt.submit', 'rt_2']])
  assert.deepEqual(env.calls.filter((c) => c.path === '/scans/scan_paused/session').at(-1).options.body, { sessionId: 'rt_2', storedSessionId: 'st_1' })
  // Finished or stopped scans offer no continue; running scans without the reason read as running.
  env.fixtures['/scans/scan_paused'].reason = null
  assert.match(render(plugin.ScanDetail({ id: 'scan_paused', onBack() {}, onFinding() {} })), /Running/)
  env.fixtures['/scans/scan_paused'].status = 'canceled'
  assert.equal(button(), undefined)
})
