const baseUrl = "https://api.myapp.com/v1";
const analyticsUrl = "https://analytics.myapp.com/track";

interface ApiResponse {
  data: unknown;
  status: number;
}

export function fetchUsers() {
  return fetch(`${baseUrl}/users`)
    .then((res) => res.json())
    .then((data) => {
      const users = data as any;
      return users;
    });
}

export function fetchPosts() {
  return fetch(`${baseUrl}/posts`)
    .then((res) => res.json())
    .then((data) => {
      return data;
    });
}

export function sendAnalytics(event: string) {
  const payload = { event, ts: Date.now() } as any;
  return fetch(analyticsUrl, {
    method: "POST",
    body: JSON.stringify(payload),
  }).then((res) => res.json());
}

export function parseConfig(raw: unknown): ApiResponse {
  const config = raw as any;
  return { data: config.value, status: 200 };
}
