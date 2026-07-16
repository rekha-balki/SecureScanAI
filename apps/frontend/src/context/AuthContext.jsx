import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { api, extractErrorMessage } from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem("ssai_user");
    return raw ? JSON.parse(raw) : null;
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("ssai_token");
    if (!token) {
      setLoading(false);
      return;
    }
    api
      .get("/auth/me")
      .then((res) => {
        setUser(res.data.data);
        localStorage.setItem("ssai_user", JSON.stringify(res.data.data));
      })
      .catch(() => {
        localStorage.removeItem("ssai_token");
        localStorage.removeItem("ssai_user");
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = async (email, password) => {
    try {
      const res = await api.post("/auth/login", { email, password });
      const { user: u, token } = res.data.data;
      localStorage.setItem("ssai_token", token.access_token);
      localStorage.setItem("ssai_user", JSON.stringify(u));
      setUser(u);
      return { ok: true };
    } catch (error) {
      return { ok: false, message: extractErrorMessage(error) };
    }
  };

  const register = async (payload) => {
    try {
      const res = await api.post("/auth/register", payload);
      const { user: u, token } = res.data.data;
      localStorage.setItem("ssai_token", token.access_token);
      localStorage.setItem("ssai_user", JSON.stringify(u));
      setUser(u);
      return { ok: true };
    } catch (error) {
      return { ok: false, message: extractErrorMessage(error) };
    }
  };

  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      // Best-effort: still clear local state even if the audit call fails
      // (e.g. token already expired) so the user isn't stuck.
    }
    localStorage.removeItem("ssai_token");
    localStorage.removeItem("ssai_user");
    setUser(null);
  };

  const value = useMemo(
    () => ({ user, loading, login, register, logout }),
    [user, loading]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
