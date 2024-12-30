import "~/styles/globals.css";

import { GeistSans } from "geist/font/sans";
import { type Metadata } from "next";
import { GoogleAnalytics } from "@next/third-parties/google";

import { TRPCReactProvider } from "~/trpc/react";

export const metadata: Metadata = {
  title: "PT. FCC Indo Jaya",
  description:
    "Bergerak dalam bidang jual-beli aksesoris garmen seperti resleting, kancing, mote-mote, karet, benang, stopper, gesper, alat tembakan merek, tali merek, lem tembak, peniti",
  icons: [{ rel: "icon", url: "/favicon.ico" }],
  openGraph: {
    type: "website",
    url: "https://fccindojaya.co.id",
    title: "PT. FCC Indo Jaya",
    description:
      "Bergerak dalam bidang jual-beli aksesoris garmen seperti resleting, kancing, mote-mote, karet, benang, stopper, gesper, alat tembakan merek, tali merek, lem tembak, peniti",
    siteName: "PT. FCC Indo Jaya",
    images: ["https://fccindojaya.co.id/logo.jpeg"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${GeistSans.variable}`}>
      <body>
        <TRPCReactProvider>{children}</TRPCReactProvider>
      </body>
      <GoogleAnalytics gaId="G-THBX57SCLS" />
    </html>
  );
}
