import { useEffect, useLayoutEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";

type Crop = { x: number; y: number; w: number; h: number };
type Handle = "move" | "n" | "s" | "e" | "w" | "nw" | "ne" | "sw" | "se";

const FULL: Crop = { x: 0, y: 0, w: 1, h: 1 };
const HANDLES: Handle[] = ["nw", "n", "ne", "e", "se", "s", "sw", "w"];

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function adjustCrop(start: Crop, handle: Handle, dx: number, dy: number, minW: number, minH: number): Crop {
  if (handle === "move") {
    return {
      x: clamp(start.x + dx, 0, 1 - start.w),
      y: clamp(start.y + dy, 0, 1 - start.h),
      w: start.w,
      h: start.h,
    };
  }
  let { x, y, w, h } = start;
  const west = handle === "w" || handle === "nw" || handle === "sw";
  const east = handle === "e" || handle === "ne" || handle === "se";
  const north = handle === "n" || handle === "nw" || handle === "ne";
  const south = handle === "s" || handle === "sw" || handle === "se";
  if (west) {
    const next = clamp(x + dx, 0, x + w - minW);
    w += x - next;
    x = next;
  }
  if (east) w = clamp(w + dx, minW, 1 - x);
  if (north) {
    const next = clamp(y + dy, 0, y + h - minH);
    h += y - next;
    y = next;
  }
  if (south) h = clamp(h + dy, minH, 1 - y);
  return { x, y, w, h };
}

function sourceSize(source: CanvasImageSource) {
  if (source instanceof HTMLImageElement) return { width: source.naturalWidth, height: source.naturalHeight };
  if (source instanceof ImageBitmap || source instanceof HTMLCanvasElement) return { width: source.width, height: source.height };
  return { width: 0, height: 0 };
}

function drawOriented(ctx: CanvasRenderingContext2D, source: CanvasImageSource, turns: number) {
  const { width, height } = sourceSize(source);
  ctx.save();
  if (turns === 1) {
    ctx.translate(height, 0);
    ctx.rotate(Math.PI / 2);
  } else if (turns === 2) {
    ctx.translate(width, height);
    ctx.rotate(Math.PI);
  } else if (turns === 3) {
    ctx.translate(0, width);
    ctx.rotate(-Math.PI / 2);
  }
  ctx.drawImage(source, 0, 0);
  ctx.restore();
}

function canvasBlob(canvas: HTMLCanvasElement, type: string, quality?: number) {
  return new Promise<Blob>((resolve, reject) => {
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("Couldn't prepare that photo."))), type, quality);
  });
}

function editedName(name: string, type: string) {
  const base = (name.split(/[/\\]/).pop() ?? "photo").replace(/[\u0000-\u001f]/g, "").trim();
  const stem = (base.replace(/\.[^.]+$/, "") || "photo").slice(0, 80);
  return `${stem}.${type === "image/png" ? "png" : "jpg"}`;
}

async function renderEdited(source: CanvasImageSource, turns: number, crop: Crop, preferPng: boolean) {
  const { width, height } = sourceSize(source);
  const orientedW = turns % 2 === 1 ? height : width;
  const orientedH = turns % 2 === 1 ? width : height;
  const sx = clamp(Math.round(crop.x * orientedW), 0, orientedW - 1);
  const sy = clamp(Math.round(crop.y * orientedH), 0, orientedH - 1);
  const sw = clamp(Math.round(crop.w * orientedW), 1, orientedW - sx);
  const sh = clamp(Math.round(crop.h * orientedH), 1, orientedH - sy);
  const maxBytes = 8 * 1024 * 1024;

  async function paint(scale: number, type: string, quality?: number) {
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(sw * scale));
    canvas.height = Math.max(1, Math.round(sh * scale));
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("Couldn't edit that photo.");
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = "high";
    ctx.save();
    ctx.scale(canvas.width / sw, canvas.height / sh);
    ctx.translate(-sx, -sy);
    drawOriented(ctx, source, turns);
    ctx.restore();
    return canvasBlob(canvas, type, quality);
  }

  let scale = Math.min(1, 2560 / Math.max(sw, sh));
  if (preferPng) {
    const png = await paint(scale, "image/png");
    if (png.size <= maxBytes) return png;
  }
  let quality = 0.92;
  let blob = await paint(scale, "image/jpeg", quality);
  while (blob.size > maxBytes && (quality > 0.5 || scale > 0.35)) {
    if (quality > 0.5) quality = Math.round((quality - 0.14) * 100) / 100;
    else scale *= 0.75;
    blob = await paint(scale, "image/jpeg", quality);
  }
  if (blob.size > maxBytes) throw new Error("The edited photo is larger than 8 MB. Crop it smaller.");
  return blob;
}

function untouched(turns: number, crop: Crop) {
  return turns === 0 && crop.x < 0.005 && crop.y < 0.005 && crop.w > 0.995 && crop.h > 0.995;
}

export function PhotoEditor({ file, onCancel, onUse }: { file: File; onCancel: () => void; onUse: (file: File) => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const frameRef = useRef<HTMLDivElement>(null);
  const bitmapRef = useRef<ImageBitmap | null>(null);
  const previewUrlRef = useRef<string | null>(null);
  const [source, setSource] = useState<ImageBitmap | HTMLImageElement | null>(null);
  const [turns, setTurns] = useState(0);
  const [crop, setCrop] = useState<Crop>(FULL);
  const [box, setBox] = useState({ w: 0, h: 0 });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setSource(null);
    setTurns(0);
    setCrop(FULL);
    setError("");
    void (async () => {
      try {
        const bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
        if (cancelled) {
          bitmap.close();
          return;
        }
        bitmapRef.current?.close();
        bitmapRef.current = bitmap;
        setSource(bitmap);
        return;
      } catch {
        // Some phone cameras hand back HEIC. The image element can still decode that.
      }
      if (cancelled) return;
      const url = URL.createObjectURL(file);
      previewUrlRef.current = url;
      const image = new Image();
      image.onload = () => {
        if (cancelled) return;
        setSource(image);
      };
      image.onerror = () => {
        if (!cancelled) setError("Couldn't open that photo.");
      };
      image.src = url;
    })();
    return () => {
      cancelled = true;
      if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
      previewUrlRef.current = null;
    };
  }, [file]);

  useEffect(() => () => {
    bitmapRef.current?.close();
    bitmapRef.current = null;
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onCancel]);

  useLayoutEffect(() => {
    if (!source) return;
    const measure = () => {
      const frame = frameRef.current;
      if (!frame) return;
      const { width, height } = sourceSize(source);
      const orientedW = turns % 2 === 1 ? height : width;
      const orientedH = turns % 2 === 1 ? width : height;
      const maxW = Math.min(480, frame.clientWidth || 480);
      const maxH = Math.min(420, window.innerHeight * 0.52);
      const scale = Math.min(maxW / orientedW, maxH / orientedH, 1);
      setBox({ w: Math.max(1, Math.round(orientedW * scale)), h: Math.max(1, Math.round(orientedH * scale)) });
    };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [source, turns]);

  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !source || box.w < 1 || box.h < 1) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(box.w * dpr);
    canvas.height = Math.round(box.h * dpr);
    canvas.style.width = `${box.w}px`;
    canvas.style.height = `${box.h}px`;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const { width, height } = sourceSize(source);
    const orientedW = turns % 2 === 1 ? height : width;
    const orientedH = turns % 2 === 1 ? width : height;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, box.w, box.h);
    ctx.save();
    ctx.scale(box.w / orientedW, box.h / orientedH);
    drawOriented(ctx, source, turns);
    ctx.restore();
  }, [source, turns, box]);

  function beginDrag(event: ReactPointerEvent<HTMLElement>, handle: Handle) {
    if (!box.w || !box.h || busy) return;
    event.preventDefault();
    event.stopPropagation();
    const startX = event.clientX;
    const startY = event.clientY;
    const start = crop;
    const minW = Math.min(0.8, 48 / box.w);
    const minH = Math.min(0.8, 48 / box.h);
    const node = event.currentTarget;
    try {
      node.setPointerCapture(event.pointerId);
    } catch {
      // The pointer can already be gone. Window listeners still track the drag.
    }
    const onMove = (ev: PointerEvent) => {
      const dx = (ev.clientX - startX) / box.w;
      const dy = (ev.clientY - startY) / box.h;
      setCrop(adjustCrop(start, handle, dx, dy, minW, minH));
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  }

  function rotate(direction: 1 | -1) {
    setTurns((current) => (current + direction + 4) % 4);
    setCrop(FULL);
  }

  async function apply() {
    if (!source || busy) return;
    const canPassThrough = file.type === "image/jpeg" || file.type === "image/png" || file.type === "image/gif" || file.type === "image/webp";
    if (canPassThrough && untouched(turns, crop)) {
      onUse(file);
      return;
    }
    setBusy(true);
    setError("");
    try {
      const blob = await renderEdited(source, turns, crop, file.type === "image/png");
      onUse(new File([blob], editedName(file.name, blob.type), { type: blob.type || "image/jpeg", lastModified: Date.now() }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Couldn't edit that photo.");
      setBusy(false);
    }
  }

  const cropStyle = {
    left: crop.x * box.w,
    top: crop.y * box.h,
    width: crop.w * box.w,
    height: crop.h * box.h,
  };

  return (
    <div className="dialog-backdrop" onMouseDown={() => { if (!busy) onCancel(); }}>
      <div
        className="dialog photo-editor"
        role="dialog"
        aria-modal="true"
        aria-label="Edit photo"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <h2>Edit photo</h2>
        <p className="hint">Rotate it, then drag the box to crop. The picture is encrypted after you use it.</p>
        <div className="photo-tools">
          <button type="button" onClick={() => rotate(-1)} disabled={!source || busy}>Rotate left</button>
          <button type="button" onClick={() => rotate(1)} disabled={!source || busy}>Rotate right</button>
          <button type="button" onClick={() => setCrop(FULL)} disabled={!source || busy}>Reset crop</button>
        </div>
        <div className="photo-frame" ref={frameRef}>
          <div className="photo-stage">
            <canvas ref={canvasRef} />
            {source && box.w > 0 && (
              <>
                <div className="crop-shade" style={{ left: 0, top: 0, right: 0, height: cropStyle.top }} />
                <div className="crop-shade" style={{ left: 0, top: cropStyle.top + cropStyle.height, right: 0, bottom: 0 }} />
                <div className="crop-shade" style={{ left: 0, top: cropStyle.top, width: cropStyle.left, height: cropStyle.height }} />
                <div className="crop-shade" style={{ left: cropStyle.left + cropStyle.width, top: cropStyle.top, right: 0, height: cropStyle.height }} />
                <div className="crop-rect" style={cropStyle} onPointerDown={(event) => beginDrag(event, "move")}>
                  <span className="crop-grid" />
                  {HANDLES.map((handle) => (
                    <button
                      key={handle}
                      type="button"
                      className={`crop-handle ${handle}`}
                      aria-label={`Crop ${handle}`}
                      onPointerDown={(event) => beginDrag(event, handle)}
                    />
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
        {error && <p className="error">{error}</p>}
        <div className="row-actions">
          <button type="button" className="text" onClick={onCancel} disabled={busy}>Cancel</button>
          <button type="button" className="primary photo-use" onClick={() => void apply()} disabled={!source || busy}>
            {busy ? "Preparing…" : "Use photo"}
          </button>
        </div>
      </div>
    </div>
  );
}
