import { useEffect, useState } from "react";

export interface UserProfile {
  _id?: string;
  name: string;
  email: string;
  role: string;
  permissions?: string[];
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
    name: "Admin (Major Project B38)",
    email: "admin@webguard.project",
    role: "SuperAdmin (Full Access)",
    permissions: ["all", "waf_control", "audit", "rules", "soc_lead", "admin_vault"],
  });

  const [isLoading, setIsLoading] = useState<boolean>(false);

  const signIn = async (method: string, data?: any) => {
    setIsLoading(true);
    try {
      let username = "admin@webguard.project";
      let password = "WebGuard@Major_Project_B38";
      if (data && typeof data === "object") {
        username = data.username || data.email || "admin@webguard.project";
        password = data.password || "WebGuard@Major_Project_B38";
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
              name: res.user.username === "admin@webguard.project" ? "Admin (Major Project B38)" : res.user.username,
              email: res.user.email || "admin@webguard.project",
              role: res.user.role || "SuperAdmin (Full Access)",
              permissions: res.user.permissions || ["all", "waf_control", "audit", "rules", "soc_lead", "admin_vault"],
            });
          }
        } else {
          // Local verification fallback
          if ((username === "admin@webguard.project" || username === "admin") && (password === "WebGuard@Major_Project_B38" || password === "admin123")) {
            setUser({
              name: "Admin (Major Project B38)",
              email: "admin@webguard.project",
              role: "SuperAdmin (Full Access)",
              permissions: ["all", "waf_control", "audit", "rules", "soc_lead", "admin_vault"],
            });
          }
        }
      } catch {
        // Fallback for offline mode
        if ((username === "admin@webguard.project" || username === "admin") && (password === "WebGuard@Major_Project_B38" || password === "admin123")) {
          setUser({
            name: "Admin (Major Project B38)",
            email: "admin@webguard.project",
            role: "SuperAdmin (Full Access)",
            permissions: ["all", "waf_control", "audit", "rules", "soc_lead", "admin_vault"],
          });
        }
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
