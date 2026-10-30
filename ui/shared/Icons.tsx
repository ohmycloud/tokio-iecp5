import { Image } from "nsh";
import type { Role } from "./store";
import { marks, glyphs } from "./icon-data";
export type IconName = keyof typeof glyphs;

/** Decorative only: the parent control keeps its visible label and accessible name. */
export function Icon(props: { name: IconName; size?: number; color?: string }) {
  return <Image src={glyphs[props.name]} resizeMode="contain" accessible={false}
    style={{ width: props.size ?? 17, height: props.size ?? 17, flexShrink: 0, tintColor: props.color ?? "#718080" }} />;
}

/** The same original role mark as the packaged app, downsampled for UI use. */
export function AppMark(props: { role: Role; size?: number }) {
  return <Image src={marks[props.role]} resizeMode="contain"
    testID="workspace-app-icon" accessibilityLabel={props.role === "server" ? "IEC104 服务端图标" : "IEC104 客户端图标"}
    style={{ width: props.size ?? 44, height: props.size ?? 44, flexShrink: 0 }} />;
}
