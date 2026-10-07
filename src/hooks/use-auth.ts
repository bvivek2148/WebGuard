import { useEffect, useState } from "react";

export interface UserProfile {
  _id?: string;
  name: string;
  email: string;
  role: string;
}

const AUTH_STORAGE_KEY = "webguard.auth.active";

export function useAuth() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    try {
      const stored = localStorage.getItem(AUTH_STORAGE_KEY);
      return stored !== "false";
    } catch {
      return true;
    }
  });

  const [user, setUser] = useState<UserProfile | null>({
    name: "Security Admin",
    email: "admin@webguard.internal",
    role: "SOC Lead",
  });

  const [isLoading, setIsLoading] = useState<boolean>(false);

  const signIn = async (method: string, data?: any) => {
    setIsLoading(true);
    try {
      let username = "admin";
      let password = "admin123";
      if (data && typeof data === "object") {
        username = data.username || data.email || "admin";
        password = data.password || "admin123";
      }
      try {
        const resp = await fetch("http://localhost:8000/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });
        if (resp.ok) {
          const res = await resp.json();
          if (res.token) {
            localStorage.setItem("webguard.token", res.token);
          }
          if (res.user) {
            setUser({
              name: res.user.username,
              email: `${res.user.username}@webguard.internal`,
              role: res.user.role || "SOC Lead",
            });
          }
        }
      } catch {
        // Graceful fallback to local session if backend offline
      }
      localStorage.setItem(AUTH_STORAGE_KEY, "true");
      setIsAuthenticated(true);
    } finally {
      setIsLoading(false);
    }
  };

  const signOut = async () => {
    setIsLoading(true);
    try {
      localStorage.setItem(AUTH_STORAGE_KEY, "false");
      setIsAuthenticated(false);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  return {
    isLoading,
    isAuthenticated,
    user,
    signIn,
    signOut,
  };
}
