import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from "react";
import { copyText, formatFields, selectionText, type ReportField } from "../report";

export type MenuItem =
  | { kind?: "item"; label: string; hint?: string; disabled?: boolean; action: () => void }
  | { kind: "sep" };

type Menu = { x: number; y: number; items: MenuItem[] };

interface ArtifactMenu {
  /** Show a custom menu and swallow the WebView/browser one. */
  open: (e: ReactMouseEvent | MouseEvent, items: MenuItem[]) => void;
  /** Copy-selection plus each field, then a combined report block. */
  openFields: (
    e: ReactMouseEvent | MouseEvent,
    fields: ReportField[],
    preferred?: string,
    extra?: MenuItem[],
  ) => void;
  copied: (label: string) => void;
}

const Ctx = createContext<ArtifactMenu | null>(null);

export function useArtifactMenu(): ArtifactMenu {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useArtifactMenu requires ContextMenuHost");
  return ctx;
}

export function ContextMenuHost({ children }: { children: ReactNode }) {
  const [menu, setMenu] = useState<Menu | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const toastTimer = useRef<number | null>(null);

  const copied = useCallback((label: string) => {
    setToast(`Copied ${label}`);
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 1400);
  }, []);

  const open = useCallback((e: ReactMouseEvent | MouseEvent, items: MenuItem[]) => {
    e.preventDefault();
    e.stopPropagation();
    if (items.length === 0) {
      setMenu(null);
      return;
    }
    setMenu({ x: e.clientX, y: e.clientY, items });
  }, []);

  const openFields = useCallback(
    (e: ReactMouseEvent | MouseEvent, fields: ReportField[], preferred?: string, extra?: MenuItem[]) => {
      const present = fields.filter((f) => f.value.length > 0);
      const items: MenuItem[] = [];
      const selected = selectionText().trim();
      if (selected) {
        items.push({
          label: "Copy selection",
          action: () => {
            void copyText(selected).then(() => copied("selection"));
          },
        });
        items.push({ kind: "sep" });
      }

      const preferredField =
        (preferred && present.find((f) => f.label === preferred)) || present[0];
      if (preferredField) {
        items.push({
          label: `Copy ${preferredField.label.toLowerCase()}`,
          action: () => {
            void copyText(preferredField.value).then(() =>
              copied(preferredField.label.toLowerCase()),
            );
          },
        });
      }

      const rest = present.filter((f) => f !== preferredField);
      for (const f of rest) {
        items.push({
          label: `Copy ${f.label.toLowerCase()}`,
          action: () => {
            void copyText(f.value).then(() => copied(f.label.toLowerCase()));
          },
        });
      }

      if (present.length > 1) {
        items.push({ kind: "sep" });
        items.push({
          label: "Copy all fields",
          hint: "labeled, for a report",
          action: () => {
            void copyText(formatFields(present)).then(() => copied("all fields"));
          },
        });
      }

      if (extra && extra.length > 0) {
        items.push({ kind: "sep" });
        items.push(...extra);
      }

      open(e, items);
    },
    [copied, open],
  );

  useEffect(() => {
    const block = (e: MouseEvent) => {
      e.preventDefault();
      const el = e.target as HTMLElement | null;
      const field = el?.closest("input, textarea") as HTMLInputElement | HTMLTextAreaElement | null;
      if (!field) return;
      const start = field.selectionStart ?? 0;
      const end = field.selectionEnd ?? 0;
      const selected = field.value.slice(start, end);
      const items: MenuItem[] = [];
      if (selected) {
        items.push({
          label: "Cut",
          action: () => {
            void copyText(selected).then(() => {
              field.setRangeText("", start, end, "end");
              field.dispatchEvent(new Event("input", { bubbles: true }));
              copied("selection");
            });
          },
        });
        items.push({
          label: "Copy",
          action: () => {
            void copyText(selected).then(() => copied("selection"));
          },
        });
      }
      items.push({
        label: "Paste",
        action: () => {
          void navigator.clipboard.readText().then((text) => {
            const s = field.selectionStart ?? field.value.length;
            const t = field.selectionEnd ?? s;
            field.setRangeText(text, s, t, "end");
            field.dispatchEvent(new Event("input", { bubbles: true }));
            copied("value");
          });
        },
      });
      open(e, items);
    };
    document.addEventListener("contextmenu", block, true);
    return () => document.removeEventListener("contextmenu", block, true);
  }, [copied, open]);

  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", onKey);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("blur", close);
    };
  }, [menu]);

  const api: ArtifactMenu = { open, openFields, copied };

  return (
    <Ctx.Provider value={api}>
      {children}
      {menu && <MenuSurface menu={menu} onClose={() => setMenu(null)} />}
      {toast && <div className="copy-toast">{toast}</div>}
    </Ctx.Provider>
  );
}

function MenuSurface({ menu, onClose }: { menu: Menu; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: menu.x, top: menu.y });

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const { innerWidth, innerHeight } = window;
    const w = el.offsetWidth;
    const h = el.offsetHeight;
    setPos({
      left: Math.min(menu.x, innerWidth - w - 8),
      top: Math.min(menu.y, innerHeight - h - 8),
    });
  }, [menu.x, menu.y, menu.items.length]);

  return (
    <div
      ref={ref}
      className="ctx-menu"
      style={{ left: pos.left, top: pos.top }}
      onMouseDown={(e) => e.stopPropagation()}
      role="menu"
    >
      {menu.items.map((item, i) =>
        item.kind === "sep" ? (
          <div key={`sep-${i}`} className="ctx-sep" />
        ) : (
          <button
            key={`${item.label}-${i}`}
            className="ctx-item"
            role="menuitem"
            disabled={item.disabled}
            onClick={() => {
              if (!item.disabled) item.action();
              onClose();
            }}
          >
            <span>{item.label}</span>
            {item.hint && <span className="ctx-hint">{item.hint}</span>}
          </button>
        ),
      )}
    </div>
  );
}
