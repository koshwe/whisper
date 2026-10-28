export function fillBrowser() {
  const root = document.documentElement;
  if (document.fullscreenElement || typeof root.requestFullscreen !== "function") return;
  void root.requestFullscreen({ navigationUI: "hide" }).catch(() => undefined);
}

export function releaseBrowser() {
  if (!document.fullscreenElement) return;
  void document.exitFullscreen().catch(() => undefined);
}
