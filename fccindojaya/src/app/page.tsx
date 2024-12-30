import { HomeComponent } from "~/app/_components/home";
import { HydrateClient } from "~/trpc/server";

export const revalidate = 3600; // invalidate every hour
export const dynamicParams = false;
export const dynamic = "force-static";

export default async function Home() {
  return (
    <HydrateClient>
      <HomeComponent></HomeComponent>
    </HydrateClient>
  );
}
