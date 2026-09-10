import { motion } from "framer-motion";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { ShieldCheck, ArrowRight } from "lucide-react";

export default function NotFound() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="min-h-screen flex flex-col bg-background text-foreground"
    >
      <div className="flex-1 flex flex-col items-center justify-center px-4">
        <div className="text-center">
          <div className="mx-auto flex size-14 items-center justify-center rounded-2xl border border-primary/30 bg-primary/10 text-primary">
            <ShieldCheck className="size-7" />
          </div>
          <h1 className="mt-6 font-mono text-6xl font-bold tracking-tight text-foreground">404</h1>
          <p className="mt-2 text-lg text-muted-foreground">Page Not Found</p>
          <p className="mx-auto mt-2 max-w-sm text-sm text-muted-foreground/80">
            The page you're looking for doesn't exist or was moved behind the firewall.
          </p>
          <Button asChild className="mt-6 gap-2 border-primary/40 bg-primary/10 text-primary hover:bg-primary/20">
            <Link to="/">
              Back to WebGuard <ArrowRight className="size-4" />
            </Link>
          </Button>
        </div>
      </div>
    </motion.div>
  );
}
