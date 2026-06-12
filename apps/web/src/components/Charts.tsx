// 纯展示型 SVG 图表组件（从 main.tsx 抽离）

// 瀑布图组件
export function WaterfallChart({ stages }: { stages: Array<{ stage: string; timestamp: number; deltaMs: number; summary: string }> }) {
  if (!stages.length) return null;
  const protocolColors: Record<string, string> = { DNS: "#4A90D9", TCP: "#7BC67E", TLS: "#E8913A", HTTP: "#9B59B6", ICMP: "#E74C3C" };
  const getColor = (stage: string) => {
    const upper = stage.toUpperCase();
    for (const [proto, color] of Object.entries(protocolColors)) {
      if (upper.includes(proto)) return color;
    }
    return "#95A5A6";
  };
  const rowH = 32, padL = 120, padR = 20, padT = 10;
  const maxDelta = Math.max(...stages.map(s => s.deltaMs), 1);
  const chartW = 500, barMaxW = chartW - padL - padR;
  const scaleX = (ms: number) => padL + (ms / maxDelta) * barMaxW;
  const totalH = padT + stages.length * rowH;
  return (
    <svg className="waterfallChart" viewBox={`0 0 ${chartW} ${totalH}`} preserveAspectRatio="xMidYMid meet">
      {stages.map((s, i) => {
        const x = scaleX(s.deltaMs);
        const color = getColor(s.stage);
        return (
          <g key={i}>
            <text x={padL - 8} y={padT + i * rowH + 16} textAnchor="end" fontSize={11} fill="var(--text-secondary)">{s.stage}</text>
            <rect x={x} y={padT + i * rowH + 2} width={Math.max(barMaxW * 0.15, 60)} height={22} fill={color} rx={3} opacity={0.85} />
            <text x={x + 6} y={padT + i * rowH + 17} fontSize={10} fill="white">{s.deltaMs.toFixed(0)}ms</text>
            {i > 0 && <line x1={scaleX(stages[i - 1].deltaMs)} y1={padT + i * rowH - 4} x2={x} y2={padT + i * rowH + 4} stroke="var(--border)" strokeDasharray="3,2" />}
          </g>
        );
      })}
    </svg>
  );
}

// 拓扑图组件
export function TopologyDiagram({ devices, dataPath, captures }: { devices: Array<{ deviceId: string; name: string; type: string; description?: string }>; dataPath: Array<{ hopIndex: number; deviceName: string }>; captures: Array<{ nodeId: string; pcapFilename?: string }> }) {
  const nodeW = 130, nodeH = 44, gapX = 180, padX = 40, padY = 30;
  const typeColors: Record<string, string> = { client: "#4A90D9", server: "#7BC67E", firewall: "#E74C3C", load_balancer: "#E8913A", switch_: "#9B59B6", router: "#1ABC9C", unknown: "#95A5A6" };
  const nodes = devices.map((d, i) => ({
    id: d.deviceId, label: d.name, type: d.type,
    x: padX + i * gapX, y: padY, color: typeColors[d.type] || typeColors.unknown,
    isCapture: captures.some(c => c.nodeId === d.deviceId)
  }));
  const edges = nodes.length > 1 ? nodes.slice(0, -1).map((n, i) => ({ from: n, to: nodes[i + 1] })) : [];
  const totalW = padX * 2 + Math.max(devices.length - 1, 0) * gapX + nodeW;
  const totalH = padY * 2 + nodeH + (nodes.some(n => n.isCapture) ? 40 : 0);
  return (
    <svg className="topologySvg" viewBox={`0 0 ${totalW} ${totalH}`} preserveAspectRatio="xMidYMid meet">
      {edges.map((e, i) => (
        <line key={i} x1={e.from.x + nodeW} y1={e.from.y + nodeH / 2} x2={e.to.x} y2={e.to.y + nodeH / 2} stroke="var(--border)" strokeWidth={2} />
      ))}
      {nodes.map((n) => (
        <g key={n.id} transform={`translate(${n.x},${n.y})`}>
          <rect width={nodeW} height={nodeH} rx={6} fill={n.color} opacity={0.9} />
          <text x={nodeW / 2} y={20} textAnchor="middle" fontSize={12} fill="white" fontWeight="bold">{n.label}</text>
          <text x={nodeW / 2} y={35} textAnchor="middle" fontSize={9} fill="rgba(255,255,255,0.8)">{n.type}</text>
          {n.isCapture && <circle cx={nodeW - 10} cy={10} r={6} fill="#FFD700" stroke="white" strokeWidth={1.5} />}
        </g>
      ))}
    </svg>
  );
}
