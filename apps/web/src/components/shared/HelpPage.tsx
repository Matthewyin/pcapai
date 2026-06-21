/*
 * HelpPage — 帮助页（阶段 1d 从 main.tsx 抽出）。
 *
 * 行为等价于原 main.tsx:1456-1508 的 <section className="helpPage">。
 * 纯静态内容（无 props / handler）。
 */
import React from "react";

export function HelpPage() {
  return (
    <section className="helpPage">
      <section className="helpHero">
        <span>Agent-first pcap 排障工作流</span>
        <h2>从聊天上传数据包，到查询通信，再点证据进 Wireshark。</h2>
        <p>
          PcapAI 适合围绕一次访问链路排障。用户在聊天里上传 pcap 并提出问题，Agent 通过 tshark-query 获取事实，再用证据卡片把通信、包和过滤器返回给你。
        </p>
      </section>

      <section className="helpGrid">
        <article>
          <strong>1. 新建会话</strong>
          <p>点击左侧新建会话会立即创建一个空 case，后续所有上传、查询和证据都围绕这个会话展开。</p>
        </article>
        <article>
          <strong>2. 在聊天中上传 pcap</strong>
          <p>可以选择、拖拽或粘贴 pcap、pcapng、cap 文件。上传后系统裁剪 payload，并自动生成最小节点信息。</p>
        </article>
        <article>
          <strong>3. Agent 追问上下文</strong>
          <p>只上传文件时，Agent 会返回抓包时间范围，并追问节点角色、抓包位置、方向、故障时间、源、目的和端口。</p>
        </article>
        <article>
          <strong>4. 创建 QueryRun</strong>
          <p>条件足够时，Agent 调用 tshark-query 构造 display filter，列出候选访问链路和关键包证据。</p>
        </article>
        <article>
          <strong>5. 打开证据</strong>
          <p>点击 conversation、packet 或 time range 证据卡片，会通过 evidence-opener 用对应过滤器打开本地 Wireshark。</p>
        </article>
        <article>
          <strong>6. 多节点链路</strong>
          <p>首版按同一五元组和时间重叠做确定性关联；遇到 NAT、F5、SSL 卸载或代理时，Agent 会追问映射线索。</p>
        </article>
        <article>
          <strong>7. 配置大模型</strong>
          <p>在配置页填写 OpenAI 兼容 Base URL、API Key 和模型名。可以保存多个配置档案并测试连通性。</p>
        </article>
        <article>
          <strong>8. 询问 Agent</strong>
          <p>Leader Agent 只解释 case graph、QueryRun 和 evidence card，不直接读取原始 pcap，也不绕过 MCP 自行判断包级事实。</p>
        </article>
      </section>

      <section className="helpPanel">
        <h2>推荐排障顺序</h2>
        <ol>
          <li>先确认每个抓包节点的角色和位置是否正确。</li>
          <li>再确认筛选条件是否命中目标访问流量。</li>
          <li>如果路径断裂，优先补 NAT/SLB/代理线索和时间偏移。</li>
          <li>最后再让 Agent 解释 finding，避免让模型替代证据判断。</li>
        </ol>
      </section>
    </section>
  );
}
