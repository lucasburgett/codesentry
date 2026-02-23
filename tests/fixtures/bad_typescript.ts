const apiUrl = "https://api.example.com/v1";

function loadData() {
  fetch(apiUrl).then((res) => res.json()).then((data) => {
    console.log(data);
    return data;
  });
}

function processResponse(response: unknown) {
  const data = response as any;
  return data.value;
}
