interface DataItem {
  id: string;
  url: string;
}

export async function fetchAllItems(items: DataItem[]) {
  const results: unknown[] = [];

  for (const item of items) {
    const res = await fetch(item.url);
    const data = await res.json();
    const typed = data as any;
    results.push(typed);
  }

  return results;
}

export async function processUrls(urls: string[]) {
  const outputs: string[] = [];

  for (const url of urls) {
    const response = await fetch(url);
    const text = await response.text();
    outputs.push(text);
  }

  return outputs;
}
