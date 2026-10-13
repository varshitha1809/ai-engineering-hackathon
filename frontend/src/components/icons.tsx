// Minimal line icons (original, stroke-based) used across the app.
import type { SVGProps } from 'react'

const base = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round', viewBox: '0 0 24 24' } as const
type P = SVGProps<SVGSVGElement>
const I = (d: string | string[]) => (p: P) => (
  <svg {...base} aria-hidden="true" {...p}>{(Array.isArray(d) ? d : [d]).map((x, i) => <path key={i} d={x} />)}</svg>
)

export const IconArrow = I('M7 17L17 7M9 7h8v8')
export const IconShield = I(['M12 3l8 3v6c0 5-3.4 8.7-8 10-4.6-1.3-8-5-8-10V6z'])
export const IconDNA = I(['M8 3c0 5 8 6 8 11s-8 6-8 7', 'M16 3c0 5-8 6-8 11s8 6 8 7', 'M8.8 7h6.4M8.8 17h6.4M10 12h4'])
export const IconGrid = I(['M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z'])
export const IconMail = I(['M3 6h18v12H3z', 'M3 7l9 6 9-6'])
export const IconSearch = I(['M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z', 'M20 20l-4-4'])
export const IconFlow = I(['M5 5h4v4H5zM15 15h4v4h-4zM15 5h4v4h-4z', 'M9 7h6M17 9v6M7 9v4a2 2 0 0 0 2 2h6'])
export const IconNodes = I(['M6 6a2 2 0 1 0 0 .1M18 6a2 2 0 1 0 0 .1M12 18a2 2 0 1 0 0 .1', 'M7.5 7.5l3.5 8.5M16.5 7.5L13 16M8 6h8'])
export const IconFlask = I(['M9 3h6M10 3v6L5 19a1.5 1.5 0 0 0 1.3 2h11.4A1.5 1.5 0 0 0 19 19l-5-10V3', 'M7.5 14h9'])
export const IconDB = I(['M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z', 'M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6', 'M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3'])
export const IconFolder = I(['M3 7h7l2 2h9v10H3z'])
export const IconCog = I(['M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.7a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.5a7 7 0 0 0 0 2.4l-2 1.5 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 21h4l.5-2.7a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.5c.1-.4.1-.8.1-1.2z'])
export const IconAlert = I(['M12 3l10 18H2z', 'M12 10v4M12 17.5v.5'])
export const IconCheck = I('M5 12l5 5 9-10')
export const IconInfo = I(['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M12 11v6M12 7.5v.5'])
export const IconBot = I(['M5 9h14v10H5z', 'M12 5v4M9 13v1M15 13v1M9 17h6', 'M12 4.5v.5'])
export const IconQuestion = I(['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5V14M12 17.5v.5'])
export const IconUpload = I(['M12 16V4M7 9l5-5 5 5', 'M4 16v4h16v-4'])
export const IconDownload = I(['M12 4v12M7 11l5 5 5-5', 'M4 20h16'])
export const IconMenu = I('M4 7h16M4 12h16M4 17h16')
export const IconPlay = I('M7 4l13 8-13 8z')
export const IconX = I('M6 6l12 12M18 6L6 18')
