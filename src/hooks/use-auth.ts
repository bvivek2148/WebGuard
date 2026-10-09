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
      let emailOrUser = "";
      let password = "";

      if (data && typeof data === "object") {
        emailOrUser = (data.email || data.username || "").trim();
        password = (data.password || "").trim();
      }

      // Guest / Anonymous login
      if (method === "anonymous" || !emailOrUser) {
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

      // Check if Master SuperAdmin: admin@webguard.project + WebGuard@Major_Project_B38
      const isMasterAdmin =
        (emailOrUser.toLowerCase() === "admin@webguard.project" || emailOrUser.toLowerCase() === "admin") &&
        (password === "WebGuard@Major_Project_B38" || password === "admin123");

      if (isMasterAdmin) {
        const adminUser: UserProfile = {
          name: "SuperAdmin (Major Project B38)",
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

      // Any other user email & password: log in as Non-Admin Operator / Analyst
      const namePart = emailOrUser.includes("@") ? emailOrUser.split("@")[0] : emailOrUser;
      const displayName = namePart ? namePart.charAt(0).toUpperCase() + namePart.slice(1) : "Operator";
      const formattedEmail = emailOrUser.includes("@") ? emailOrUser : `${emailOrUser}@webguard.local`;

      const nonAdminUser: UserProfile = {
        name: displayName,
        email: formattedEmail,
        role: "Analyst / Operator (Non-Admin)",
        isSuperAdmin: false,
        permissions: ["overview", "traffic", "audit", "sandbox"],
      };

      setUser(nonAdminUser);
      try {
        localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(nonAdminUser));
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
