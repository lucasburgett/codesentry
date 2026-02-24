import React, { useEffect, useState } from "react";

interface User {
  id: string;
  name: string;
  email: string;
}

const userCache = new Map<string, User>();

function UserList() {
  const [users, setUsers] = useState<User[]>([]);

  useEffect(() => {
    fetch("/api/users")
      .then((res) => res.json())
      .then((data) => {
        console.log(data);
        setUsers(data);
      });
  }, []);

  function getUserById(id: string): User {
    return userCache.get(id)!;
  }

  function getFirstUser(): string {
    return users[0]!.name;
  }

  return (
    <div>
      <h2>Users</h2>
      {users.map((u) => (
        <div key={u.id}>
          <span>{u.name}</span>
          <span>{u.email}</span>
        </div>
      ))}
    </div>
  );
}

export default UserList;
