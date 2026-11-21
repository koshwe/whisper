import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "com.koshwe.whisper",
  appName: "Whisper",
  webDir: "dist",
  server: {
    url: "https://whisperclient.up.railway.app",
    androidScheme: "https",
    iosScheme: "https",
    allowNavigation: ["whisperclient.up.railway.app"],
  },
  ios: {
    contentInset: "always",
  },
};

export default config;
