/*
 * Resizer — 三栏之间的拖拽手柄。
 *
 * 设计取自 docs/ui-design/three-column-light.html：
 *   .resizer { width:5px; cursor:col-resize; hover/dragging 高亮 + ::after 竖条 }
 *
 * 行为：
 *   - mousedown 锁定 startX/startWidth，document 级 mousemove 实时回调 onDrag
 *   - 右栏拖拽方向反转（往左拖增大宽度）
 *   - mouseup 时一次性 onCommit 最终宽度（父级写回 useUIStore，persist 落 localStorage）
 *
 * 实时拖拽用本地 state（父级），mouseup 才落库 store —— 避免 mousemove 高频写 localStorage。
 * 阶段 2 三栏新 UI 第 1 步。
 */
import React from "react";

type ResizerProps = {
  /** 拖拽方向：左栏往右拖增大（+1），右栏往左拖增大（-1） */
  direction: 1 | -1;
  /** 起始宽度（mousedown 时父级读取的当前宽度） */
  getWidth: () => number;
  /** 拖拽中实时更新（受控宽度，让父级即时重渲染，但不落库） */
  onDrag: (width: number) => void;
  /** 拖拽结束回调（落库 useUIStore，setter 自带 clamp） */
  onCommit: (width: number) => void;
};

export function Resizer({ direction, getWidth, onDrag, onCommit }: ResizerProps) {
  const [dragging, setDragging] = React.useState(false);

  const onMouseDown = React.useCallback(
    (event: React.MouseEvent<HTMLDivElement>) => {
      event.preventDefault();
      setDragging(true);
      const startX = event.clientX;
      const startW = getWidth();
      let currentW = startW;

      const onMove = (ev: MouseEvent) => {
        currentW = startW + (ev.clientX - startX) * direction;
        onDrag(currentW);
      };
      const onUp = () => {
        setDragging(false);
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        onCommit(currentW);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    },
    [direction, getWidth, onDrag, onCommit]
  );

  return (
    <div
      className={`resizer ${dragging ? "dragging" : ""}`}
      role="separator"
      aria-orientation="vertical"
      onMouseDown={onMouseDown}
    />
  );
}
