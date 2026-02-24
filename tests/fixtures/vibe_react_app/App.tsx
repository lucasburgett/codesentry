import React, { useEffect, useState } from "react";

const apiUrl = "https://api.myapp.com/v1";

interface Post {
  id: number;
  title: string;
  body: string;
}

function App() {
  const [posts, setPosts] = useState<Post[]>([]);
  const [html, setHtml] = useState("");

  useEffect(() => {
    fetch(`${apiUrl}/posts`)
      .then((res) => res.json())
      .then((data) => {
        console.log(data);
        setPosts(data);
      });

    fetch(`${apiUrl}/content`)
      .then((res) => res.text())
      .then((text) => setHtml(text));
  }, []);

  return (
    <div>
      <h1>My Blog</h1>
      <div dangerouslySetInnerHTML={{ __html: html }} />
      <ul>
        {posts.map((p) => (
          <li key={p.id}>{p.title}</li>
        ))}
      </ul>
    </div>
  );
}

export default App;
