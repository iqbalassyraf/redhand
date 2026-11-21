import React from "react";
import Image from "next/image";

export interface RedHandCrestProps {
  /** "tile" renders the rounded-square crimson emblem; "mark" renders the floating 5-petal hollow-core mark. */
  variant?: "tile" | "mark";
  size?: "sm" | "md" | "lg";
  className?: string;
}

const SIZE_MAP = {
  sm: { px: 28, cls: "h-7 w-7" },
  md: { px: 36, cls: "h-9 w-9" },
  lg: { px: 40, cls: "h-10 w-10" },
} as const;

/** Official RedHand 5-petal hollow-core brand crest. */
export function RedHandCrest({
  variant = "tile",
  size = "md",
  className = "",
}: RedHandCrestProps) {
  const dim = SIZE_MAP[size];
  const src = variant === "mark" ? "/redhand-mark.png" : "/redhand-icon.png";

  return (
    <Image
      src={src}
      alt="RedHand"
      width={dim.px}
      height={dim.px}
      priority
      unoptimized
      className={`${dim.cls} shrink-0 select-none object-contain ${
        variant === "tile" ? "rounded-xl shadow-rh-crimson" : ""
      } ${className}`}
    />
  );
}
