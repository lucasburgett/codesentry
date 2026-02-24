import React, { useEffect, useState } from "react";

interface User {
  id: string;
  name: string;
  email: string;
}

function UserDirectory() {
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadUsers() {
      try {
        const res = await fetch("/api/users");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: User[] = await res.json();
        setUsers(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error");
      }
    }
    loadUsers();
  }, []);

  if (error) {
    return <div role="alert">Failed to load users: {error}</div>;
  }

  return (
    <div>
      <h2>User Directory</h2>
      {users.map((user) => (
        <div key={user.id}>
          <span>{user.name}</span>
          <span>{user.email}</span>
        </div>
      ))}
    </div>
  );
}

export default UserDirectory;
