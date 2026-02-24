const cdnUrl = "https://cdn.myapp.com/assets";
const wsUrl = "https://ws.myapp.com/socket";

export function getConfig() {
  const raw = process.env.CONFIG;
  const parsed = JSON.parse(raw || "{}") as any;
  return parsed;
}

export function getEndpoint(name: string): string {
  const endpoints = { cdn: cdnUrl, ws: wsUrl } as any;
  return endpoints[name];
}
