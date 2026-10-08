import { useEffect, useState } from "react";

export interface UserProfile {
  _id?: string;
  name: string;
  email: string;
  role: string;
  isSuperAdmin: boolean;
  permissions?: string[];
}

const AUTH_STORAGE_KEY = "webguard.auth.active";
const USER_STORAGE_KEY = "webguard.auth.user";

export function useAuth() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    try {
      const stored = localStorage.getItem(AUTH_STORAGE_KEY);
      return stored !== "false";
    } catch {
      return true;
    }
  });

  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      const storedUser = localStorage.getItem(USER_STORAGE_KEY);
      if (storedUser) {
        return JSON.parse(storedUser);
      }
    } catch {
      // ignore
    }
    return {
      name: "Admin (Major Project B38)",
      email: "admin@webguard.project",
      role: "SuperAdmin (Full Access)",
      isSuperAdmin: true,
      permissions: ["all", "waf_control", "audit", "rules", "soc_lead", "admin_vault"],
    };
  });

  const [isLoading, setIsLoading] = useState<boolean>(false);

  const signIn = async (method: string, data?: any) => {
    setIsLoading(true);
    try {
      let username = "admin@webguard.project";
      let password = "WebGuard@Major_Project_B38";

      if (data && typeof data === "object") {
        username = (data.username || data.email || "").trim();
        password = data.password || "";
      }

      // Guest / Anonymous login
      if (method === "anonymous" || !username) {
        const guestUser: UserProfile = {
          name: "Guest Visitor",
          email: "guest@webguard.local",
          role: "Guest (View Only)",
          isSuperAdmin: false,
          permissions: ["overview", "traffic", "view"],
        };
        setUser(guestUser);
        try {
          localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(guestUser));
          localStorage.setItem(AUTH_STORAGE_KEY, "true");
        } catch { /* ignore */ }
        setIsAuthenticated(true);
        return;
      }

      // Check if Master SuperAdmin
      const isMasterAdmin =
        (username.toLowerCase() === "admin@webguard.project" || username.toLowerCase() === "admin") &&
        (password === "WebGuard@Major_Project_B38" || password === "admin123");

      if (isMasterAdmin) {
        const adminUser: UserProfile = {
          name: "Admin (Major Project B38)",
          email: "admin@webguard.project",
          role: "SuperAdmin (Full Access)",
          isSuperAdmin: true,
          permissions: ["all", "waf_control", "audit", "rules", "soc_lead", "admin_vault"],
        };
        setUser(adminUser);
        try {
          localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(adminUser));
          localStorage.setItem(AUTH_STORAGE_KEY, "true");
        } catch { /* ignore */ }
        setIsAuthenticated(true);
        return;
      }

      // Any other username / email & password: Allow login as standard Guest / Analyst
      const displayName = username.includes("@") ? username.split("@")[0] : username;
      const formattedEmail = username.includes("@") ? username : `${username}@user.local`;
      const regularUser: UserProfile = {
        name: displayName.charAt(0).toUpperCase() + displayName.slice(1),
        email: formattedEmail,
        role: "Guest / Analyst (Limited View)",
        isSuperAdmin: false,
        permissions: ["overview", "traffic", "audit", "sandbox"],
      };

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
            regularUser.role = res.user.role || regularUser.role;
            regularUser.isSuperAdmin = res.user.role?.includes("SuperAdmin") || false;
          }
        }
      } catch {
        // Local fallback
      }

      setUser(regularUser);
      try {
        localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(regularUser));
        localStorage.setItem(AUTH_STORAGE_KEY, "true");
      } catch { /* ignore */ }
      setIsAuthenticated(true);
    } finally {
      setIsLoading(false);
    }
  };

  const signOut = async () => {
    setIsLoading(true);
    try {
      localStorage.setItem(AUTH_STORAGE_KEY, "false");
      localStorage.removeItem(USER_STORAGE_KEY);
      localStorage.removeItem("webguard.token");
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
