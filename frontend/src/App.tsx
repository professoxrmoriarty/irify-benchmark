import { useEffect, useMemo, useState } from 'react';
import type { BenchmarkDataset, CaseItem, FamilyMetric, PendingItem, ProjectIndex, ProjectIndexEntry, ToolKey, ToolMetric } from './types';

const STATUS_LABELS: Record<string, string> = {
  hit_exact: '准确命中',
  hit_downgraded: '降级命中',
  covered_missed: '漏报',
  warning_matched: '低风险命中',
  warning_missed: '低风险漏报',
  warning_overstated: '风险等级虚高',
  correct_negative: '负例成功拦截',
  advisory_noise: '提示性噪声',
  severe_false_positive: '严重误报',
  uncovered_by_rule: '规则未覆盖',
  hit_unknown: '人工待定',
};

const TOOL_LABELS: Record<ToolKey, string> = {
  irify: 'IRify',
  code_guard: '代码卫士',
  fortify: 'Fortify',
};

const TABS = [
  { key: 'overview', label: '总览' },
  { key: 'cases', label: '案例' },
  { key: 'pending', label: '待复核' },
] as const;

type TabKey = (typeof TABS)[number]['key'];

export default function App() {
  const [projectIndex, setProjectIndex] = useState<ProjectIndex | null>(null);
  const [currentProjectId, setCurrentProjectId] = useState<string>('');
  const [data, setData] = useState<BenchmarkDataset | null>(null);
  const [view, setView] = useState<'projects' | 'detail'>('projects');
  const [tab, setTab] = useState<TabKey>('overview');
  const [tool, setTool] = useState<ToolKey>('irify');
  const [family, setFamily] = useState('all');
  const [status, setStatus] = useState('all');
  const [keyword, setKeyword] = useState('');
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [pendingTool, setPendingTool] = useState<'all' | ToolKey>('all');
  const [pendingKeyword, setPendingKeyword] = useState('');
  const [selectedPendingKey, setSelectedPendingKey] = useState<string | null>(null);

  useEffect(() => {
    fetch('./data/index.json')
      .then((response) => response.json())
      .then((payload: ProjectIndex) => {
        setProjectIndex(payload);
        setCurrentProjectId('');
      })
      .catch(async () => {
        const fallback = await fetch('./data/javaseclab-benchmark.json').then((response) => response.json());
        setData(fallback);
        setView('detail');
      });
  }, []);

  const currentProject = useMemo<ProjectIndexEntry | null>(
    () => projectIndex?.projects.find((item) => item.projectId === currentProjectId) ?? null,
    [projectIndex, currentProjectId],
  );

  useEffect(() => {
    if (!currentProject || view !== 'detail') return;
    fetch(currentProject.frontendPath)
      .then((response) => response.json())
      .then((payload: BenchmarkDataset) => {
        setData(payload);
        setSelectedCaseId(payload.cases[0]?.caseId ?? null);
        setSelectedPendingKey(payload.pendingReviewAdditions[0] ? buildPendingKey(payload.pendingReviewAdditions[0]) : null);
        setFamily('all');
        setStatus('all');
        setKeyword('');
        setPendingTool('all');
        setPendingKeyword('');
      });
  }, [currentProject, view]);

  const activeTool = useMemo(
    () => data?.tools.find((item) => item.key === tool) ?? null,
    [data, tool],
  );

  const filteredCases = useMemo(() => {
    if (!data) return [];
    return data.cases.filter((item) => {
      if (family !== 'all' && item.family !== family) return false;
      if (status !== 'all' && item.verificationStatus[tool] !== status) return false;
      if (!keyword) return true;
      const haystack = [
        item.caseId,
        item.title,
        item.ruleType,
        item.route,
        item.filePath,
        item.family,
        item.description,
      ].join(' ').toLowerCase();
      return haystack.includes(keyword.toLowerCase());
    });
  }, [data, family, keyword, status, tool]);

  const selectedCase = useMemo(
    () => filteredCases.find((item) => item.caseId === selectedCaseId) ?? data?.cases.find((item) => item.caseId === selectedCaseId) ?? null,
    [data, filteredCases, selectedCaseId],
  );

  const filteredPending = useMemo(() => {
    if (!data) return [];
    return data.pendingReviewAdditions.filter((item) => {
      if (pendingTool !== 'all' && item.tool !== pendingTool) return false;
      if (!pendingKeyword) return true;
      const haystack = [item.ruleName, item.filePath, item.evidence, item.reason].join(' ').toLowerCase();
      return haystack.includes(pendingKeyword.toLowerCase());
    });
  }, [data, pendingKeyword, pendingTool]);

  const selectedPending = useMemo(() => {
    if (!selectedPendingKey) return filteredPending[0] ?? null;
    return filteredPending.find((item) => buildPendingKey(item) === selectedPendingKey) ?? filteredPending[0] ?? null;
  }, [filteredPending, selectedPendingKey]);
  const activePendingPolicy = data?.pendingReviewPolicy?.tools?.[tool];
  const hasEffectivePending = !!data && (data.pendingReviewAdditions.length > 0 || data.tools.some((item) => item.pending_review_additions > 0));
  const visibleTabs = hasEffectivePending ? TABS : TABS.filter((item) => item.key !== 'pending');

  useEffect(() => {
    if (!selectedCaseId && filteredCases[0]) {
      setSelectedCaseId(filteredCases[0].caseId);
      return;
    }
    if (selectedCaseId && !filteredCases.some((item) => item.caseId === selectedCaseId)) {
      setSelectedCaseId(filteredCases[0]?.caseId ?? null);
    }
  }, [filteredCases, selectedCaseId]);

  useEffect(() => {
    if (!selectedPendingKey && filteredPending[0]) {
      setSelectedPendingKey(buildPendingKey(filteredPending[0]));
      return;
    }
    if (selectedPendingKey && !filteredPending.some((item) => buildPendingKey(item) === selectedPendingKey)) {
      setSelectedPendingKey(filteredPending[0] ? buildPendingKey(filteredPending[0]) : null);
    }
  }, [filteredPending, selectedPendingKey]);

  useEffect(() => {
    if (!hasEffectivePending && tab === 'pending') {
      setTab('overview');
    }
  }, [hasEffectivePending, tab]);

  if (projectIndex && view === 'projects') {
    return (
      <ProjectLanding
        projectIndex={projectIndex}
        onSelect={(projectId) => {
          setCurrentProjectId(projectId);
          setView('detail');
          setTab('overview');
        }}
      />
    );
  }

  if (!data || !activeTool) {
    return <div className="loading-shell">载入中</div>;
  }

  const compactMetrics = [
    { label: '案例', value: data.summary.totalCases },
    { label: '正例', value: data.summary.positiveCases },
    { label: '应提示', value: data.summary.warnCases },
    { label: '负例', value: data.summary.negativeCases },
    { label: '规则', value: data.meta.rule_count },
  ];

  return (
    <div className="app-shell">
      <aside className="side-nav">
        <div className="project-block">
          <span className="project-kicker">评估台</span>
          <h1>{data.project}</h1>
        </div>

        {projectIndex && (
          <section className="side-section">
            <div className="side-label">项目</div>
            <button className="back-to-projects" onClick={() => setView('projects')}>
              返回靶场列表
            </button>
            <label className="field">
              <select value={currentProjectId} onChange={(event) => { setCurrentProjectId(event.target.value); setTab('overview'); }}>
                {processedProjects(projectIndex).map((item) => (
                  <option key={item.projectId} value={item.projectId}>
                    {item.projectName}
                  </option>
                ))}
              </select>
            </label>
          </section>
        )}

        <nav className="nav-tabs">
          {visibleTabs.map((item) => (
            <button key={item.key} className={item.key === tab ? 'nav-tab active' : 'nav-tab'} onClick={() => setTab(item.key)}>
              {item.label}
            </button>
          ))}
        </nav>

        <section className="side-section">
          <div className="side-label">工具</div>
          <div className="tool-list">
            {data.tools.map((item) => (
              <button key={item.key} className={item.key === tool ? 'tool-card active' : 'tool-card'} onClick={() => setTool(item.key)}>
                <div>
                  <strong>{item.label}</strong>
                  <span>{formatPercent(item.high_risk_overreport_rate)} 高危过报</span>
                </div>
                {item.pending_review_additions > 0 && (
                  <div className="tool-card-pending">
                    <strong>{item.pending_review_additions}</strong> 有效待复核
                  </div>
                )}
              </button>
            ))}
          </div>
        </section>

        <section className="side-section">
          <div className="side-label">基线</div>
          <div className="side-stats">
            {compactMetrics.map((item) => (
              <div key={item.label} className="side-stat">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </section>
      </aside>

      <main className="workspace">
        <header className="workspace-header">
          <div>
            <div className="workspace-title">{TOOL_LABELS[tool]}</div>
            <div className="workspace-subtitle">{tabLabel(tab)}</div>
          </div>
          <div className="header-stats">
            <HeaderStat label="扩展召回" value={formatPercent(activeTool.positive_relaxed_recall)} sub={`${activeTool.positive_relaxed_tp} / ${activeTool.positive_supported} 规则覆盖案例`} tone="good" />
            <HeaderStat label="已审噪声" value={formatPercent(activeTool.finding_noise_rate)} sub={`${activeTool.finding_noise_total} / ${activeTool.finding_reviewed_total} 已审告警`} tone="danger" />
            <HeaderStat label="高危过报" value={formatPercent(activeTool.high_risk_overreport_rate)} sub={`${activeTool.high_risk_confirmed_false_positive + activeTool.high_risk_overstated} / ${activeTool.high_risk_reviewed_total} 高危已审`} tone="danger" />
            {activeTool.pending_review_additions > 0 && (
              <HeaderStat
                label="有效待复核"
                value={String(activeTool.pending_review_additions)}
                sub={activePendingPolicy ? `原始额外告警 ${activeTool.pending_review_raw}，已过滤 ${activeTool.pending_review_excluded}` : `原始额外告警 ${activeTool.pending_review_raw}`}
                tone="neutral"
              />
            )}
          </div>
        </header>

        {tab === 'overview' && <OverviewView data={data} tool={tool} activeTool={activeTool} onPickFamily={setFamily} onSwitchTab={setTab} onSwitchTool={setTool} />}
        {tab === 'cases' && (
          <CasesView
            data={data}
            tool={tool}
            family={family}
            setFamily={setFamily}
            status={status}
            setStatus={setStatus}
            keyword={keyword}
            setKeyword={setKeyword}
            filteredCases={filteredCases}
            selectedCase={selectedCase}
            selectedCaseId={selectedCaseId}
            setSelectedCaseId={setSelectedCaseId}
          />
        )}
        {hasEffectivePending && tab === 'pending' && (
          <PendingView
            data={data}
            pendingTool={pendingTool}
            setPendingTool={setPendingTool}
            pendingKeyword={pendingKeyword}
            setPendingKeyword={setPendingKeyword}
            filteredPending={filteredPending}
            selectedPending={selectedPending}
            selectedPendingKey={selectedPendingKey}
            setSelectedPendingKey={setSelectedPendingKey}
            onJumpCase={(caseId) => {
              setSelectedCaseId(caseId);
              setTab('cases');
            }}
          />
        )}
      </main>
    </div>
  );
}


function ProjectLanding({ projectIndex, onSelect }: { projectIndex: ProjectIndex; onSelect: (projectId: string) => void }) {
  const readyProjects = processedProjects(projectIndex);
  const hiddenCount = Math.max(projectIndex.projects.length - readyProjects.length, 0);
  const totals = readyProjects.reduce(
    (acc, item) => {
      acc.cases += item.summary?.totalCases ?? 0;
      acc.supported += item.summary?.supportedCases ?? 0;
      acc.negative += item.summary?.negativeCases ?? 0;
      return acc;
    },
    { cases: 0, supported: 0, negative: 0 },
  );

  return (
    <main className="landing-shell">
      <section className="landing-hero">
        <div>
          <span className="project-kicker">Benchmark</span>
          <h1>已处理靶场</h1>
          <p>先看已经完成复核和基线回刷的样本。进入靶场后再看三家工具的召回、误报、过报和案例明细。</p>
        </div>
        <div className="landing-stats">
          <div><span>靶场</span><strong>{readyProjects.length}</strong></div>
          <div><span>案例</span><strong>{totals.cases}</strong></div>
          <div><span>规则覆盖</span><strong>{totals.supported}</strong></div>
          <div><span>负例</span><strong>{totals.negative}</strong></div>
        </div>
      </section>

      <section className="project-grid">
        {readyProjects.map((item) => {
          const pendingTotal = sumPending(item.pendingReviewTotals);
          return (
            <button key={item.projectId} className="project-card" onClick={() => onSelect(item.projectId)}>
              <div className="project-card-head">
                <div>
                  <span>{item.language || 'unknown'}</span>
                  <strong>{item.projectName}</strong>
                </div>
                <em>{pendingTotal === 0 ? '已处理' : `${pendingTotal} 待复核`}</em>
              </div>
              <div className="project-card-metrics">
                <div><span>案例</span><strong>{item.summary?.totalCases ?? 0}</strong></div>
                <div><span>正例</span><strong>{item.summary?.positiveCases ?? 0}</strong></div>
                <div><span>负例</span><strong>{item.summary?.negativeCases ?? 0}</strong></div>
                <div><span>覆盖</span><strong>{item.summary?.supportedCases ?? 0}</strong></div>
              </div>
              <div className="project-card-foot">查看具体数据</div>
            </button>
          );
        })}
      </section>

      {hiddenCount > 0 && (
        <div className="landing-note">
          还有 {hiddenCount} 个样本仍在整理或只有原始扫描数据，暂不放进首页主列表。
        </div>
      )}
    </main>
  );
}

function processedProjects(projectIndex: ProjectIndex): ProjectIndexEntry[] {
  return projectIndex.projects.filter((item) => (item.summary?.totalCases ?? 0) > 0 && sumPending(item.pendingReviewTotals) === 0);
}

function sumPending(value?: Record<ToolKey, number>): number {
  if (!value) return 0;
  return (value.irify ?? 0) + (value.code_guard ?? 0) + (value.fortify ?? 0);
}

const RADAR_COLORS: Record<ToolKey, string> = {
  irify: '#3f6fd6',
  code_guard: '#248a52',
  fortify: '#c65353',
};

const RADAR_AXES = [
  { label: '扩展召回', getValue: (t: ToolMetric) => t.positive_relaxed_recall ?? 0 },
  { label: '审计纯度', getValue: (t: ToolMetric) => 1 - (t.finding_noise_rate ?? 0) },
  { label: '高危质量', getValue: (t: ToolMetric) => 1 - (t.high_risk_overreport_rate ?? 0) },
  { label: '低风险覆盖', getValue: (t: ToolMetric) => t.warn_match_rate ?? 0 },
];

function RadarChart({ tools, activeTool }: { tools: ToolMetric[]; activeTool: ToolKey }) {
  const SIZE = 300;
  const cx = SIZE / 2;
  const cy = SIZE / 2;
  const R = 96;
  const n = RADAR_AXES.length;
  const angles = Array.from({ length: n }, (_, i) => (i / n) * 2 * Math.PI);
  const toXY = (angle: number, r: number) => ({
    x: cx + r * Math.sin(angle),
    y: cy - r * Math.cos(angle),
  });
  const gridLevels = [0.25, 0.5, 0.75, 1];
  const sorted = [...tools].sort((a) => (a.key === activeTool ? 1 : -1));
  return (
    <div className="radar-wrap">
      <svg width="100%" viewBox={`0 0 ${SIZE} ${SIZE}`}>
        {gridLevels.map((level) => {
          const pts = angles.map((a) => { const { x, y } = toXY(a, level * R); return `${x},${y}`; }).join(' ');
          return <polygon key={level} points={pts} fill="none" stroke="#e6e5e1" strokeWidth={level === 1 ? 1.5 : 1} />;
        })}
        {angles.map((angle, i) => {
          const { x, y } = toXY(angle, R);
          return <line key={i} x1={cx} y1={cy} x2={x} y2={y} stroke="#e6e5e1" strokeWidth={1} />;
        })}
        {sorted.map((t) => {
          const pts = angles.map((angle, i) => {
            const val = Math.max(0, Math.min(1, RADAR_AXES[i].getValue(t)));
            const { x, y } = toXY(angle, val * R);
            return `${x},${y}`;
          }).join(' ');
          const color = RADAR_COLORS[t.key];
          const isActive = t.key === activeTool;
          return (
            <polygon key={t.key} points={pts} fill={color} fillOpacity={isActive ? 0.18 : 0.06}
              stroke={color} strokeWidth={isActive ? 2 : 1} strokeOpacity={isActive ? 1 : 0.5} />
          );
        })}
        {angles.map((angle, i) => {
          const { x, y } = toXY(angle, R + 16);
          return (
            <text key={i} x={x} y={y} textAnchor="middle" dominantBaseline="middle"
              fontSize={9} fill="#70757d" fontFamily="inherit">
              {RADAR_AXES[i].label}
            </text>
          );
        })}
        <circle cx={cx} cy={cy} r={2} fill="#d8d6d1" />
      </svg>
      <div className="radar-legend">
        {tools.map((t) => (
          <div key={t.key} className={`radar-legend-item${t.key === activeTool ? ' is-active' : ''}`}>
            <span className="radar-dot" style={{ background: RADAR_COLORS[t.key] }} />
            {t.label}
          </div>
        ))}
      </div>
    </div>
  );
}

function buildToolInsight(tools: ToolMetric[]): string {
  const byRecall = [...tools].sort((a, b) => (b.positive_relaxed_recall ?? 0) - (a.positive_relaxed_recall ?? 0));
  const byNoise = [...tools].sort((a, b) => (a.finding_noise_rate ?? 1) - (b.finding_noise_rate ?? 1));
  const bestRecall = byRecall[0];
  const bestNoise = byNoise[0];
  const parts = [`${bestRecall.label} 扩展召回最高（${formatPercent(bestRecall.positive_relaxed_recall)}）`];
  if (bestNoise.key !== bestRecall.key) {
    parts.push(`${bestNoise.label} 已审噪声最低（${formatPercent(bestNoise.finding_noise_rate)}）`);
  }
  return parts.join('；') + '。';
}

function OverviewView({
  data,
  tool,
  activeTool,
  onPickFamily,
  onSwitchTab,
  onSwitchTool,
}: {
  data: BenchmarkDataset;
  tool: ToolKey;
  activeTool: ToolMetric;
  onPickFamily: (value: string) => void;
  onSwitchTab: (value: TabKey) => void;
  onSwitchTool: (value: ToolKey) => void;
}) {
  const familyRank = [...data.families].sort((left, right) => {
    const leftRisk = familyScore(left.tools[tool] ?? {});
    const rightRisk = familyScore(right.tools[tool] ?? {});
    return rightRisk - leftRisk;
  });
  const hasEffectivePending = data.pendingReviewAdditions.length > 0 || data.tools.some((item) => item.pending_review_additions > 0);

  return (
    <>
      <div className="tool-insight-banner">
        <span className="insight-dot" />
        {buildToolInsight(data.tools)}
      </div>

      <div className="overview-grid">
      <section className="panel metrics-panel">
        <PanelTitle title="关键对比指标" />
        <div className="kpi-grid">
          <KpiCard label="有效信号" value={`${activeTool.finding_useful_alerts}`} sub="已确认能帮助定位问题的告警数" tone="good" />
          <KpiCard label="已审噪声" value={`${activeTool.finding_noise_total}`} sub="确认误报 + 降级噪声 + 高危过报" tone="warn" />
          <KpiCard label="审计负担" value={formatRatio(activeTool.finding_audit_load)} sub="每发现 1 个真信号平均要处理多少条告警" tone="neutral" />
          <KpiCard label="规则缺失" value={String(activeTool.unsupported_cases)} sub="无规则映射，不纳入召回计算" tone="danger" />
        </div>
      </section>

      <section className="panel board-panel">
        <PanelTitle title="工具对比" />
        <div className="board-table">
          {data.tools.map((item) => (
              <button key={item.key} className={item.key === tool ? 'board-row active' : 'board-row'} onClick={() => onSwitchTool(item.key)}>
              <div className="board-main">
                <strong>{item.label}</strong>
                <span>{item.positive_relaxed_tp}/{item.positive_supported}</span>
              </div>
              <div className="board-values">
                <MetricValue label="严格召回" value={formatPercent(item.positive_recall)} better="higher" title="仅计精确等级命中，高表示工具发现完整、准确" />
                <MetricValue label="扩展召回" value={formatPercent(item.positive_relaxed_recall)} better="higher" title="含降级命中（工具报了低一级也算），更接近实际发现能力" />
                <MetricValue label="已审噪声" value={formatPercent(item.finding_noise_rate)} better="lower" title="已复核告警中，最终被证明是噪声或等级过高的比例。越低越好" />
                <MetricValue label="高危过报" value={formatPercent(item.high_risk_overreport_rate)} better="lower" title="高危/严重告警里，落到 safe 或 should_warn 的比例。越低越好" />
                {item.pending_review_additions > 0 && (
                  <MetricValue label="有效待复核" value={String(item.pending_review_additions)} title={`当前人工复核队列。原始额外告警 ${item.pending_review_raw}`} />
                )}
              </div>
            </button>
          ))}
        </div>
      </section>

      <section className="panel trend-panel">
        <PanelTitle title="三层指标" />
        <div className="bar-panel">
          <RateBar label="严格召回" value={activeTool.positive_recall} tone="good" />
          <RateBar label="扩展召回" value={activeTool.positive_relaxed_recall} tone="good" />
          <RateBar label="已审噪声率" value={activeTool.finding_noise_rate} tone="warn" />
          <RateBar label="高危过报率" value={activeTool.high_risk_overreport_rate} tone="danger" />
          {activeTool.pending_review_additions > 0 && <RateBar label="待复核率" value={activeTool.finding_pending_rate} tone="neutral" />}
        </div>
      </section>

      <section className="panel radar-panel">
        <PanelTitle title="多维对比（当前工具加粗）" />
        <RadarChart tools={data.tools} activeTool={tool} />
      </section>

      <section className="panel panel-span-2">
        <PanelTitle title="高危原始审计负担" />
        <div className="burden-panel">
          {data.tools.map((item) => (
            <div key={`high-burden-${item.key}`} className={item.key === tool ? 'burden-card active' : 'burden-card'}>
              <div className="burden-head">
                <strong>{item.label}</strong>
                <span>{formatPercent(item.high_risk_overreport_rate)} 高危过报</span>
              </div>
              <div className="burden-grid">
                <div>
                  <span>原始高危额外</span>
                  <strong>{item.pending_review_high_raw ?? 0}</strong>
                </div>
                <div>
                  <span>高危有效待复核</span>
                  <strong>{item.pending_review_high_kept ?? 0}</strong>
                </div>
                <div>
                  <span>高危已审</span>
                  <strong>{item.high_risk_reviewed_total}</strong>
                </div>
                <div>
                  <span>高危已过滤</span>
                  <strong>{item.pending_review_high_excluded ?? 0}</strong>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel panel-span-2">
        <PanelTitle title="家族热区" />
        <div className="family-board">
          {familyRank.map((item) => (
            <button
              key={item.family}
              className="family-row"
              onClick={() => {
                onPickFamily(item.family);
                onSwitchTab('cases');
              }}
            >
              <div className="family-main">
                <strong>{item.family}</strong>
                <span>正例 {item.positiveCases} / 负例 {item.safeCases}</span>
              </div>
              <div className="family-statuses">
                {buildFamilyTags(item.tools[tool] ?? {}).map((tag) => (
                  <span key={`${item.family}-${tag.label}`} className={`inline-tag ${tag.tone}`}>
                    {tag.label} {tag.value}
                  </span>
                ))}
              </div>
            </button>
          ))}
        </div>
      </section>

      <section className="panel panel-span-2 glossary-panel">
        <PanelTitle title="指标说明" />
        <div className="glossary-grid">
          <div className="glossary-item">
            <strong>发现能力</strong>
            <span>仍然看严格召回和扩展召回。扩展召回会把“有命中但等级降了”的情况算进去，更贴近实际发现能力。</span>
          </div>
          <div className="glossary-item">
            <strong>审计负担</strong>
            <span>看已审噪声率、待复核 kept/raw、每真信号审查量。它们比单纯 case 误报率更接近研发实际使用体验。</span>
          </div>
          <div className="glossary-item">
            <strong>分级质量</strong>
            <span>高危误报只看 safe 被打成高危/严重；高危过报再把 should_warn 被抬成高危也算进去，更能反映分级是否稳。</span>
          </div>
          {hasEffectivePending && (
            <div className="glossary-item">
              <strong>有效待复核</strong>
              <span>只表示当前仍需要人工继续判断的队列；原始额外告警规模会单独展示，不再和待复核写成一个分数。</span>
            </div>
          )}
        </div>
      </section>
    </div>
    </>
  );
}

function CasesView(props: {
  data: BenchmarkDataset;
  tool: ToolKey;
  family: string;
  setFamily: (value: string) => void;
  status: string;
  setStatus: (value: string) => void;
  keyword: string;
  setKeyword: (value: string) => void;
  filteredCases: CaseItem[];
  selectedCase: CaseItem | null;
  selectedCaseId: string | null;
  setSelectedCaseId: (value: string | null) => void;
}) {
  const { data, tool, family, setFamily, status, setStatus, keyword, setKeyword, filteredCases, selectedCase, selectedCaseId, setSelectedCaseId } = props;

  return (
    <div className="cases-shell">
      <section className="toolbar panel slim">
        <div className="toolbar-grid">
          <Field label="家族">
            <select value={family} onChange={(event) => setFamily(event.target.value)}>
              <option value="all">全部</option>
              {data.families.map((item) => (
                <option key={item.family} value={item.family}>{item.family}</option>
              ))}
            </select>
          </Field>
          <Field label="状态">
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option value="all">全部</option>
              {Object.entries(data.statusLegend).map(([key, label]) => (
                <option key={key} value={key}>{label}</option>
              ))}
            </select>
          </Field>
          <Field label="检索">
            <input value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder="case / route / 文件 / 描述" />
          </Field>
        </div>
      </section>

      {(family !== 'all' || status !== 'all') && (
        <div className="active-filters">
          {family !== 'all' && (
            <button className="active-filter-chip" onClick={() => setFamily('all')}>
              家族: {family} <span>×</span>
            </button>
          )}
          {status !== 'all' && (
            <button className="active-filter-chip" onClick={() => setStatus('all')}>
              状态: {data.statusLegend[status] ?? status} <span>×</span>
            </button>
          )}
        </div>
      )}

      <div className="inspector-layout">
        <section className="panel list-panel">
          <div className="list-header">
            <strong>{filteredCases.length} 条</strong>
            <div className="list-summary">
              <span>命中 {countStatuses(filteredCases, tool, ['hit_exact', 'hit_downgraded', 'warning_matched'])}</span>
              <span>漏报 {countStatuses(filteredCases, tool, ['covered_missed', 'warning_missed'])}</span>
              <span>高危过报 {countStatuses(filteredCases, tool, ['severe_false_positive', 'warning_overstated'])}</span>
              <span>降级噪声 {countStatuses(filteredCases, tool, ['advisory_noise'])}</span>
              {countStatuses(filteredCases, tool, ['uncovered_by_rule']) > 0 && (
                <span className="uncovered-count">无覆盖 {countStatuses(filteredCases, tool, ['uncovered_by_rule'])}</span>
              )}
            </div>
          </div>
          <div className="case-list">
            {filteredCases.map((item) => (
              <button
                key={item.caseId}
                className={[
                  item.caseId === selectedCaseId ? 'list-row active' : 'list-row',
                  item.verificationStatus[tool] === 'uncovered_by_rule' ? 'list-row--uncovered' : '',
                ].filter(Boolean).join(' ')}
                onClick={() => setSelectedCaseId(item.caseId)}
              >
                <div className="row-top">
                  <strong>{item.caseId}</strong>
                  <span className={expectationChipClass(item.expectation)}>{expectationLabel(item.expectation)}</span>
                </div>
                <div className="row-title">{item.title}</div>
                <div className="row-meta">
                  <span>{item.family}</span>
                  <span>{item.filePath}:{item.lineStart}</span>
                </div>
                <span className={`status-pill ${statusTone(item.verificationStatus[tool])}`}>
                  {STATUS_LABELS[item.verificationStatus[tool]] ?? item.verificationStatus[tool]}
                </span>
              </button>
            ))}
          </div>
        </section>

        <section className="panel inspector-panel">
          {selectedCase ? <CaseInspector item={selectedCase} tool={tool} /> : <div className="empty-state">没有符合条件的案例</div>}
        </section>
      </div>
    </div>
  );
}

function PendingView(props: {
  data: BenchmarkDataset;
  pendingTool: 'all' | ToolKey;
  setPendingTool: (value: 'all' | ToolKey) => void;
  pendingKeyword: string;
  setPendingKeyword: (value: string) => void;
  filteredPending: PendingItem[];
  selectedPending: PendingItem | null;
  selectedPendingKey: string | null;
  setSelectedPendingKey: (value: string | null) => void;
  onJumpCase: (caseId: string) => void;
}) {
  const { data, pendingTool, setPendingTool, pendingKeyword, setPendingKeyword, filteredPending, selectedPending, selectedPendingKey, setSelectedPendingKey, onJumpCase } = props;
  const [pendingLimit, setPendingLimit] = useState(30);
  useEffect(() => { setPendingLimit(30); }, [pendingTool, pendingKeyword]);
  const visiblePending = filteredPending.slice(0, pendingLimit);
  const activePolicy = pendingTool === 'all' ? null : data.pendingReviewPolicy?.tools?.[pendingTool];

  return (
    <div className="pending-shell">
      <section className="toolbar panel slim">
        <div className="toolbar-grid pending-toolbar">
          <Field label="工具">
            <select value={pendingTool} onChange={(event) => setPendingTool(event.target.value as 'all' | ToolKey)}>
              <option value="all">全部</option>
              {data.tools.map((item) => (
                <option key={item.key} value={item.key}>{item.label}</option>
              ))}
            </select>
          </Field>
          <Field label="检索">
            <input value={pendingKeyword} onChange={(event) => setPendingKeyword(event.target.value)} placeholder="规则 / 文件 / 证据" />
          </Field>
        </div>
        <div className="empty-note" style={{ marginTop: 12 }}>
          {activePolicy
            ? `当前列表已按 OWASP Top10 + 紧急度清洗：raw ${activePolicy.rawTotal} → kept ${activePolicy.keptTotal}，过滤 ${activePolicy.excludedTotal}。`
            : '当前列表展示的是 kept 队列；raw 代表工具原始额外告警规模。'}
        </div>
      </section>

      <div className="inspector-layout">
        <section className="panel list-panel">
          <div className="list-header">
            <strong>{filteredPending.length} 条</strong>
            <div className="pending-summary">
              {data.tools.map((item) => (
                <button key={item.key} className={pendingTool === item.key ? 'mini-filter active' : 'mini-filter'} onClick={() => setPendingTool(item.key)}>
                  {item.label} {item.pending_review_additions}
                </button>
              ))}
            </div>
          </div>
          <div className="pending-list">
            {visiblePending.map((item) => {
              const pendingKey = buildPendingKey(item);
              return (
                <button
                  key={pendingKey}
                  className={pendingKey === selectedPendingKey ? 'list-row active' : 'list-row'}
                  onClick={() => setSelectedPendingKey(pendingKey)}
                >
                  <div className="row-top">
                    <span className="tool-badge">{item.toolLabel}</span>
                    <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span>
                  </div>
                  <div className="row-title">{item.ruleName}</div>
                  <div className="row-meta">
                    <span>{item.owaspCategory}</span>
                    <span>{item.filePath}</span>
                    <span>line {item.lineStart}</span>
                  </div>
                </button>
              );
            })}
            {filteredPending.length > pendingLimit && (
              <button className="list-more-btn" onClick={() => setPendingLimit((l) => l + 50)}>
                显示更多 · 剩余 {filteredPending.length - pendingLimit} 条
              </button>
            )}
          </div>
        </section>

        <section className="panel inspector-panel">
          {selectedPending ? <PendingInspector item={selectedPending} onJumpCase={onJumpCase} /> : <div className="empty-state">没有符合条件的新增项</div>}
        </section>
      </div>
    </div>
  );
}

function CaseInspector({ item, tool }: { item: CaseItem; tool: ToolKey }) {
  const currentStatus = item.verificationStatus[tool];

  return (
    <div className="min-w-0">
      <div className="inspector-head">
        <div className="min-w-0">
          <div className="inspector-kicker">{item.family}</div>
          <h2 className="wrap-anywhere">{item.title}</h2>
          <div className="inspector-sub truncate" title={item.route || item.filePath}>{item.route || item.filePath}</div>
        </div>
        <div className="head-tags">
          <span className={expectationChipClass(item.expectation)}>{expectationLabel(item.expectation)}</span>
          <span className={`status-pill large ${statusTone(currentStatus)}`}>{TOOL_LABELS[tool]} · {STATUS_LABELS[currentStatus] ?? currentStatus}</span>
        </div>
      </div>

      <div className="info-grid">
        <InfoCell label="样本位置" value={`${item.filePath}:${item.lineStart}-${item.lineEnd}`} />
        <InfoCell label="风险类别" value={item.ruleType} />
        <InfoCell label="期望等级" value={item.expectedSeverityBand.length ? item.expectedSeverityBand.join(' / ') : '未指定'} />
        <InfoCell label="IRify 支持状态" value={item.irifySupport === 'supported' ? `已覆盖 (${item.ruleCandidates.length} 候选规则)` : '规则暂未覆盖'} />
      </div>

      <div className="inspector-sections">
        <section className="panel inset">
          <PanelTitle title="差异分析 (工具结论对照)" />
          <div className="status-grid">
            {(['irify', 'code_guard', 'fortify'] as ToolKey[]).map((key) => (
              <div key={key} className={`status-card ${statusTone(item.verificationStatus[key])}`}>
                <span>{TOOL_LABELS[key]}</span>
                <strong>{STATUS_LABELS[item.verificationStatus[key]] ?? item.verificationStatus[key]}</strong>
              </div>
            ))}
          </div>
        </section>

        {(['covered_missed', 'severe_false_positive', 'warning_overstated', 'advisory_noise'] as string[]).includes(currentStatus) && (
          <section className="panel inset action-panel">
            <PanelTitle title="规则优化指引" />
            <div className="action-hint">
              {currentStatus === 'covered_missed' ? (
                <p><strong>漏报分析：</strong>当前样本被标记为漏报。建议检查是否存在该风险类型的 Source/Sink 规则缺失，或 IRify 中间语言转换过程中丢失了关键语义。</p>
              ) : currentStatus === 'warning_overstated' ? (
                <p><strong>高危过报：</strong>当前样本本应只是低中危提示，却被抬成了高危/严重。优先检查规则里的消毒函数、白名单和约束分支有没有进入降级路径。</p>
              ) : currentStatus === 'advisory_noise' ? (
                <p><strong>降级噪声：</strong>当前样本没有造成高危误报，但仍产生了低/中危提示。建议评估这类提示是否真有审计价值，避免用户被大量低价值告警淹没。</p>
              ) : (
                <p><strong>误报分析：</strong>当前样本存在严重误报。建议核对“保护措施”部分，检查是否缺失了对应的 Sanitize (净化) 规则，或 Sink 规则匹配过于宽泛。</p>
              )}
            </div>
          </section>
        )}

        <section className="panel inset">
          <PanelTitle title="数据流关键节点 (Trace Stack)" />
          <div className="trace-grid">
            <TraceCard label="输入源 (Source)" location={item.source} />
            {item.sink ? <TraceCard label="触发点 (Sink)" location={item.sink} /> : null}
            {item.trace.slice(2).map((trace, index) => (
              <TraceCard key={`${trace.file_path}-${trace.line_start}-${index}`} label={`中间节点 ${index + 1}`} location={trace} />
            ))}
          </div>
        </section>

        <section className="panel inset split">
          <div>
            <PanelTitle title="命中规则" />
            <div className="observed-grid">
              {(['irify', 'code_guard', 'fortify'] as ToolKey[]).map((key) => (
                <div key={key} className="observed-card">
                  <div className="observed-title">{TOOL_LABELS[key]}</div>
                  {(item.observedRules[key] ?? []).length === 0 ? (
                    <div className="empty-note">无</div>
                  ) : (
                    (item.observedRules[key] ?? []).map((rule) => (
                      <div key={`${key}-${rule.rule_name}-${rule.line_start}`} className="observed-item">
                        <strong>{rule.rule_name}</strong>
                        <span>{rule.severity} · line {rule.line_start}</span>
                        <p>{rule.evidence}</p>
                      </div>
                    ))
                  )}
                </div>
              ))}
            </div>
          </div>
          <div>
            <PanelTitle title="保护措施 / 备注" />
            <div className="notes-stack">
              {(item.safeGuards ?? []).length === 0 ? (
                <div className="empty-note">无显式保护措施</div>
              ) : (
                item.safeGuards.map((guard) => (
                  <div key={`${guard.line}-${guard.type}`} className="guard-card">
                    <strong>{guard.description}</strong>
                    <span>line {guard.line}</span>
                    <code>{guard.code}</code>
                  </div>
                ))
              )}
              {(item.notes ?? []).length > 0 && (
                <ul className="note-list">
                  {item.notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function PendingInspector({ item, onJumpCase }: { item: PendingItem; onJumpCase: (caseId: string) => void }) {
  return (
    <>
      <div className="inspector-head">
        <div>
          <div className="inspector-kicker">{item.toolLabel}</div>
          <h2>{item.ruleName}</h2>
          <div className="inspector-sub">{item.filePath}:{item.lineStart}</div>
        </div>
        <span className={`severity-pill large ${severityTone(item.severity)}`}>{item.severity}</span>
      </div>

      <div className="info-grid two-col">
        <InfoCell label="位置" value={`${item.filePath}:${item.lineStart}`} />
        <InfoCell label="OWASP" value={item.owaspCategory || '-'} />
        <InfoCell label="优先级" value={item.reviewPriority === 'high' ? '高' : '中'} />
        <InfoCell label="原因" value={item.reason} />
      </div>

      <div className="inspector-sections">
        <section className="panel inset">
          <PanelTitle title="证据" />
          <div className="evidence-box">{item.evidence || '无'}</div>
        </section>

        <section className="panel inset">
          <PanelTitle title="候选 case" />
          {item.candidateCaseIds.length === 0 ? (
            <div className="empty-note">暂无候选 case</div>
          ) : (
            <div className="candidate-links">
              {item.candidateCaseIds.map((caseId) => (
                <button key={caseId} className="candidate-link" onClick={() => onJumpCase(caseId)}>
                  {caseId}
                </button>
              ))}
            </div>
          )}
        </section>
      </div>
    </>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

function HeaderStat({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone: 'good' | 'danger' | 'neutral' }) {
  return (
    <div className={`header-stat ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {sub && <em className="header-stat-sub">{sub}</em>}
    </div>
  );
}

function KpiCard({ label, value, sub, tone }: { label: string; value: string; sub: string; tone: 'good' | 'warn' | 'danger' | 'neutral' }) {
  return (
    <div className={`kpi-card ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <em>{sub}</em>
    </div>
  );
}

function MetricValue({ label, value, better, title }: { label: string; value: string; better?: 'higher' | 'lower'; title?: string }) {
  return (
    <div className="metric-value" title={title}>
      <span>{label}{better === 'higher' ? ' ↑' : better === 'lower' ? ' ↓' : ''}</span>
      <strong className={better === 'higher' ? 'mv-good' : better === 'lower' ? 'mv-danger' : ''}>{value}</strong>
    </div>
  );
}

function RateBar({ label, value, tone }: { label: string; value: number | null; tone: 'good' | 'danger' | 'warn' | 'neutral' }) {
  const width = value ? `${Math.round(value * 100)}%` : '0%';
  return (
    <div className="rate-row">
      <span>{label}</span>
      <div className="rate-track">
        <div className={`rate-fill ${tone}`} style={{ width }} />
      </div>
      <strong>{formatPercent(value)}</strong>
    </div>
  );
}

function PanelTitle({ title }: { title: string }) {
  return <div className="panel-title">{title}</div>;
}

function InfoCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="info-cell">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function TraceCard({ label, location }: { label: string; location: CaseItem['source'] }) {
  return (
    <div className="trace-card">
      <div className="trace-label">{label}</div>
      <strong>{location.api ?? location.symbol ?? location.kind ?? '-'}</strong>
      <span>{location.file_path ?? '-'}:{location.line_start ?? '-'}</span>
      {location.notes && <p>{location.notes}</p>}
      {location.evidence && <p>{location.evidence}</p>}
    </div>
  );
}

function countStatuses(cases: CaseItem[], tool: ToolKey, statuses: string[]) {
  return cases.filter((item) => statuses.includes(item.verificationStatus[tool])).length;
}

function familyScore(counter: Record<string, number>) {
  return (counter.severe_false_positive ?? 0) * 5 + (counter.covered_missed ?? 0) * 4 + (counter.warning_overstated ?? 0) * 3 + (counter.hit_downgraded ?? 0) * 2 + (counter.hit_exact ?? 0);
}

function buildFamilyTags(counter: Record<string, number>) {
  const items = [
    { key: 'hit_exact', label: '命中', tone: 'good' },
    { key: 'hit_downgraded', label: '降级', tone: 'warn' },
    { key: 'covered_missed', label: '漏报', tone: 'danger' },
    { key: 'severe_false_positive', label: '严重误报', tone: 'danger' },
    { key: 'advisory_noise', label: '提示', tone: 'warn' },
  ];

  return items
    .filter((item) => (counter[item.key] ?? 0) > 0)
    .map((item) => ({ ...item, value: counter[item.key] ?? 0 }));
}

function expectationLabel(value: CaseItem['expectation']) {
  if (value === 'must_alert') return '应命中';
  if (value === 'should_warn') return '应提示';
  if (value === 'must_not_alert') return '不应命中';
  return '信息项';
}

function expectationChipClass(value: CaseItem['expectation']) {
  if (value === 'must_alert') return 'expect-pill alert';
  if (value === 'should_warn') return 'expect-pill warn';
  if (value === 'must_not_alert') return 'expect-pill safe';
  return 'expect-pill neutral';
}

function statusTone(status: string) {
  if (['hit_exact', 'correct_negative'].includes(status)) return 'good';
  if (['hit_downgraded', 'warning_matched', 'advisory_noise', 'hit_unknown'].includes(status)) return 'warn';
  if (['severe_false_positive', 'warning_overstated', 'covered_missed', 'warning_missed'].includes(status)) return 'danger';
  return 'neutral';
}

function severityTone(severity: string) {
  const lowered = severity.toLowerCase();
  if (['critical', 'high', '严重', '高危'].includes(lowered)) return 'danger';
  if (['medium', '中危'].includes(lowered)) return 'warn';
  return 'neutral';
}

function buildPendingKey(item: PendingItem) {
  return `${item.tool}-${item.ruleName}-${item.filePath}-${item.lineStart}`;
}

function formatPercent(value: number | null) {
  if (value === null || Number.isNaN(value)) return '-';
  return `${(value * 100).toFixed(1)}%`;
}

function formatRatio(value: number | null) {
  if (value === null || Number.isNaN(value)) return '-';
  return `${value.toFixed(2)}x`;
}

function tabLabel(tab: TabKey) {
  if (tab === 'overview') return '数据看板';
  if (tab === 'cases') return '案例检视';
  return '待复核审单';
}
