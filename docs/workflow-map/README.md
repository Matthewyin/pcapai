# pcapAI 工作流程地图

这个目录用于维护一个可交互的包/组件流程地图。

- `flows.json`：事实源，记录节点、流程和传递方式。
- `index.html`：单页展示器，只读取 `flows.json`。

## 本地预览

浏览器直接打开 `index.html` 时，可能因为 `file://` 限制无法读取 `flows.json`。建议从本目录启动静态服务：

```bash
cd docs/workflow-map
python3 -m http.server 30026
```

然后访问：

```text
http://localhost:30026/
```

## 维护原则

1. `nodes` 放页面上所有包、组件、配置、MCP 和外部工具。
2. `flows` 放可点击的操作流程。
3. 每个 `steps[].from` 和 `steps[].to` 必须引用已有 `nodes.id`。
4. `method` 必须说明传递方式，例如 `HTTP API`、`SSE events`、`stdio MCP`、`JSON file write`、`CLI subprocess`。
5. 当前仓库没有实现的流程必须标记为 `status: "example"`，不要混成真实实现。

## 新增流程模板

```json
{
  "id": "new-flow-id",
  "label": "新的操作名称",
  "category": "runtime",
  "status": "implemented",
  "summary": "一句话说明这个流程解决什么问题。",
  "steps": [
    {
      "from": "web",
      "to": "routes",
      "method": "HTTP API",
      "label": "POST /api/example",
      "payload": "请求里传递的数据"
    }
  ]
}
```

## 当前边界

第一版不是自动扫描代码生成的架构图，而是手工维护的文档事实源。好处是表达清楚、可控；代价是新增流程时需要同步更新 `flows.json`。
