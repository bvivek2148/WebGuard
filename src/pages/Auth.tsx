import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useAuth } from "@/hooks/use-auth";
import { motion } from "framer-motion";
import {
  ArrowRight,
  CheckCircle2,
  Crosshair,
  Eye,
  EyeOff,
  Key,
  Loader2,
  Lock,
  Mail,
  ScanSearch,
  ShieldCheck,
  UserX,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";

interface AuthProps {
  redirectAfterAuth?: string;
}

function resolveRedirectAfterAuth(
  returnTo: string | null,
  fallback = "/dashboard",
) {
  if (returnTo?.startsWith("/") && !returnTo.startsWith("//")) {
    return returnTo;
  }
  return fallback;
}

const STEPS = [
  {
    icon: ScanSearch,
    step: "01 · Audit",
    body: "Score any origin across 6 security pillars with raw HTTP evidence.",
    tone: "text-wg-rose border-wg-rose/30 bg-wg-rose/10",
  },
  {
    icon: ShieldCheck,
    step: "02 · Shield",
    body: "Flip the firewall to BLOCKING and virtual patches deploy instantly.",
    tone: "text-wg-cyan border-wg-cyan/30 bg-wg-cyan/10",
  },
  {
    icon: Crosshair,
    step: "03 · Verify",
    body: "Re-scan and watch posture leap to 100/100 — proven in a comparison matrix.",
    tone: "text-wg-emerald border-wg-emerald/30 bg-wg-emerald/10",
  },
];

function Auth({ redirectAfterAuth }: AuthProps = {}) {
  const { isLoading: authLoading, isAuthenticated, signIn } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const redirect = resolveRedirectAfterAuth(
    searchParams.get("returnTo"),
    redirectAfterAuth,
  );
  const [step, setStep] = useState<"signIn" | { email: string }>("signIn");
  const [email, setEmail] = useState("admin@webguard.project");
  const [password, setPassword] = useState("WebGuard@Major_Project_B38");
  const [showPassword, setShowPassword] = useState(false);
  const [otp, setOtp] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [postSignIn, setPostSignIn] = useState(false);

  useEffect(() => {
    if (!authLoading && isAuthenticated && postSignIn) {
      navigate(redirect);
    }
  }, [authLoading, isAuthenticated, postSignIn, navigate, redirect]);

  const handleCredentialsSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      await signIn("credentials", { email, username: email.split("@")[0] || email, password });
      setPostSignIn(true);
    } catch (error) {
      console.error("Sign-in error:", error);
      setError("Failed to sign in. Please check your credentials.");
      setIsLoading(false);
    }
  };

  const handleOtpSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      const formData = new FormData(event.currentTarget);
      await signIn("email-otp", formData);
      setPostSignIn(true);
    } catch (error) {
      console.error("OTP verification error:", error);
      setError("The verification code you entered is incorrect.");
      setIsLoading(false);
      setOtp("");
    }
  };

  const handleGuestLogin = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await signIn("anonymous");
      setPostSignIn(true);
    } catch (error) {
      console.error("Guest login error:", error);
      setError(
        `Failed to sign in as guest: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
      setIsLoading(false);
    }
  };

  return (
    <div className="wg-grid-bg relative min-h-screen overflow-hidden bg-background text-foreground">
      {/* ambient glows */}
      <div className="pointer-events-none absolute -top-32 -left-32 h-[420px] w-[420px] rounded-full bg-primary/[0.08] blur-[110px]" />
      <div className="pointer-events-none absolute -bottom-40 -right-32 h-[460px] w-[460px] rounded-full bg-wg-emerald/[0.07] blur-[110px]" />

      {/* top bar */}
      <div className="relative z-20 mx-auto flex w-full max-w-6xl items-center justify-between px-5 py-5">
        <Link to="/" className="flex items-center gap-2.5">
          <div className="flex size-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400 to-emerald-400 shadow-[0_0_24px_rgba(34,211,238,0.35)]">
            <ShieldCheck className="size-5 text-[#04121c]" />
          </div>
          <div className="leading-tight">
            <p className="text-base font-bold tracking-tight">
              WebGuard<span className="text-wg-cyan">.</span>
            </p>
            <p className="text-[9px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">
              AI WAF · SOC Console
            </p>
          </div>
        </Link>
        <div className="flex items-center gap-2.5">
          <ThemeToggle />
          <Button
            asChild
            variant="ghost"
            size="sm"
            className="h-8 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <Link to="/">
              Back to site <ArrowRight className="size-3.5" />
            </Link>
          </Button>
        </div>
      </div>

      {/* split layout */}
      <div className="relative z-10 mx-auto flex w-full max-w-6xl flex-col items-center justify-center gap-12 px-5 pb-16 pt-4 lg:flex-row lg:items-center lg:gap-16 lg:pt-8">
        {/* brand story */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="hidden w-full max-w-md lg:block"
        >
          <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
            Security Operations Center
          </p>
          <h1 className="mt-4 text-4xl font-bold leading-[1.1] tracking-tight">
            Your edge.
            <br />
            <span className="bg-gradient-to-r from-wg-cyan via-primary to-wg-emerald bg-clip-text text-transparent">
              Audited, shielded, proven.
            </span>
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
            Sign in to run a baseline vulnerability audit, activate virtual
            patching with one toggle, and verify a 100/100 posture — all inside
            a live SOC with AI threat analysis.
          </p>

          <div className="mt-8 flex flex-col gap-3">
            {STEPS.map((s) => (
              <div
                key={s.step}
                className="flex items-start gap-3 rounded-xl border border-border/50 bg-card/60 p-3.5"
              >
                <div
                  className={`flex size-9 shrink-0 items-center justify-center rounded-lg border ${s.tone}`}
                >
                  <s.icon className="size-4" />
                </div>
                <div>
                  <p className="text-xs font-semibold text-foreground">{s.step}</p>
                  <p className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">
                    {s.body}
                  </p>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 flex items-center gap-4 text-[11px] text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="size-3.5 text-wg-emerald" /> FastAPI WAF Connected
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="size-3.5 text-wg-emerald" /> Real-Time ML Inspection
            </span>
          </div>
        </motion.div>

        {/* auth card */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.08 }}
          className="w-full max-w-md"
        >
          <Card className="border-border/60 bg-card/90 shadow-[0_30px_80px_-30px_rgba(1,6,18,0.6)] backdrop-blur">
            {step === "signIn" ? (
              <>
                <CardHeader className="text-center pb-3">
                  <div className="mx-auto flex size-12 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400 to-emerald-400 shadow-[0_0_24px_rgba(34,211,238,0.3)]">
                    <ShieldCheck className="size-6 text-[#04121c]" />
                  </div>
                  <CardTitle className="mt-3 text-xl font-bold">Welcome to WebGuard</CardTitle>
                  <CardDescription className="text-xs">
                    Sign in to access AI WAF Security Operations Center
                  </CardDescription>
                </CardHeader>
                <form onSubmit={handleCredentialsSubmit}>
                  <CardContent className="space-y-4">
                    {/* Email / Username */}
                    <div className="space-y-1.5">
                      <label className="block text-xs font-semibold text-foreground">
                        Email or Username
                      </label>
                      <div className="relative">
                        <Mail className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
                        <Input
                          name="email"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                          placeholder="admin@webguard.project"
                          type="text"
                          className="pl-9 h-10 text-xs font-medium"
                          disabled={isLoading}
                          required
                        />
                      </div>
                    </div>

                    {/* Password */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <label className="block text-xs font-semibold text-foreground">
                          Password
                        </label>
                        <span className="text-[10px] text-muted-foreground font-medium">Major Project B38</span>
                      </div>
                      <div className="relative">
                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
                        <Input
                          name="password"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          placeholder="••••••••"
                          type={showPassword ? "text" : "password"}
                          className="pl-9 pr-10 h-10 text-xs font-medium"
                          disabled={isLoading}
                          required
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition"
                          tabIndex={-1}
                        >
                          {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                        </button>
                      </div>
                    </div>

                    {error && <p className="text-xs font-medium text-wg-rose">{error}</p>}

                    {/* Submit Button */}
                    <Button
                      type="submit"
                      className="w-full h-10 gap-2 font-bold text-xs bg-primary text-primary-foreground hover:bg-primary/90 shadow-md transition"
                      disabled={isLoading}
                    >
                      {isLoading ? (
                        <>
                          <Loader2 className="size-4 animate-spin" /> Signing In...
                        </>
                      ) : (
                        <>
                          <Key className="size-3.5" /> Sign In to Dashboard <ArrowRight className="size-3.5" />
                        </>
                      )}
                    </Button>

                    {/* Quick Demo Credentials */}
                    <div className="flex items-center justify-center gap-1.5 pt-1 text-[11px] text-muted-foreground">
                      <span>SuperAdmin:</span>
                      <button
                        type="button"
                        onClick={() => {
                          setEmail("admin@webguard.project");
                          setPassword("WebGuard@Major_Project_B38");
                        }}
                        className="rounded bg-muted px-2 py-0.5 font-mono text-[10px] font-semibold text-foreground hover:bg-muted/80 transition"
                      >
                        👑 admin@webguard.project
                      </button>
                    </div>

                    <div className="pt-2">
                      <div className="relative">
                        <div className="absolute inset-0 flex items-center">
                          <span className="w-full border-t border-border/60" />
                        </div>
                        <div className="relative flex justify-center text-xs uppercase">
                          <span className="bg-card px-2 text-muted-foreground text-[10px] font-semibold">Or</span>
                        </div>
                      </div>

                      <Button
                        type="button"
                        variant="outline"
                        className="mt-3 w-full h-9 gap-2 text-xs font-semibold"
                        onClick={handleGuestLogin}
                        disabled={isLoading}
                      >
                        <UserX className="size-4" />
                        Continue as Guest
                      </Button>
                    </div>
                  </CardContent>
                </form>
              </>
            ) : (
              <>
                <CardHeader className="mt-4 text-center">
                  <CardTitle>Check your email</CardTitle>
                  <CardDescription>
                    We've sent a code to {step.email}
                  </CardDescription>
                </CardHeader>
                <form onSubmit={handleOtpSubmit}>
                  <CardContent className="pb-4">
                    <input type="hidden" name="email" value={step.email} />
                    <input type="hidden" name="code" value={otp} />

                    <div className="flex justify-center">
                      <InputOTP
                        value={otp}
                        onChange={setOtp}
                        maxLength={6}
                        disabled={isLoading}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && otp.length === 6 && !isLoading) {
                            const form = (e.target as HTMLElement).closest("form");
                            if (form) form.requestSubmit();
                          }
                        }}
                      >
                        <InputOTPGroup>
                          {Array.from({ length: 6 }).map((_, index) => (
                            <InputOTPSlot key={index} index={index} />
                          ))}
                        </InputOTPGroup>
                      </InputOTP>
                    </div>
                    {error && (
                      <p className="mt-2 text-center text-sm text-wg-rose">{error}</p>
                    )}
                    <p className="mt-4 text-center text-sm text-muted-foreground">
                      Didn't receive a code?{" "}
                      <Button
                        variant="link"
                        className="h-auto p-0"
                        onClick={() => setStep("signIn")}
                      >
                        Try again
                      </Button>
                    </p>
                  </CardContent>
                  <CardFooter className="flex-col gap-2">
                    <Button
                      type="submit"
                      className="w-full"
                      disabled={isLoading || otp.length !== 6}
                    >
                      {isLoading ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Verifying...
                        </>
                      ) : (
                        <>
                          Verify code
                          <ArrowRight className="ml-2 h-4 w-4" />
                        </>
                      )}
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      onClick={() => setStep("signIn")}
                      disabled={isLoading}
                      className="w-full"
                    >
                      Use different email
                    </Button>
                  </CardFooter>
                </form>
              </>
            )}

            <div className="rounded-b-lg border-t bg-muted/40 px-6 py-3 text-center text-[11px] text-muted-foreground">
              Active Security Monitoring · Enterprise Threat Defense
            </div>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}

export default function AuthPage(props: AuthProps) {
  return <Auth {...props} />;
}
