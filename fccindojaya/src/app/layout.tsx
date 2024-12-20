import "~/styles/globals.css";

import { GeistSans } from "geist/font/sans";
import { type Metadata } from "next";

import { TRPCReactProvider } from "~/trpc/react";

export const metadata: Metadata = {
  title: "FCC Indo Jaya",
  description:
    "FCC Indo Jaya | Bergerak dalam bidang jual-beli aksesoris garmen seperti resleting, kancing, mote-mote, karet, benang, stopper, gesper, alat tembakan merek, tali merek, lem tembak, peniti",
  icons: [{ rel: "icon", url: "/favicon.ico" }],
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${GeistSans.variable}`}>
      <body>
        <TRPCReactProvider>{children}</TRPCReactProvider>
      </body>
    </html>
  );
}
