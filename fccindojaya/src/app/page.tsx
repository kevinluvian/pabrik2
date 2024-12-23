import { HomeComponent } from "~/app/_components/home";
import { HydrateClient } from "~/trpc/server";

export default async function Home() {
  return (
    <HydrateClient>
      <HomeComponent></HomeComponent>
    </HydrateClient>
  );
}
