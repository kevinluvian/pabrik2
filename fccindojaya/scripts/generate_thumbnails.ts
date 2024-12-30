import sharp from "sharp";
import fs from "fs";

// How to run:
// npx ts-node -O '{"module": "commonjs"}' generatePaySlip.ts
// DATABASE_URL="postgresql://plastindo:AVNS_dz48ck9Rtzp-u97llna@skleem-prod-do-user-7647921-0.a.db.ondigitalocean.com:25060/plastindonewdb?sslmode=require" npx ts-node -O '{"module": "commonjs"}' amendData.ts

async function main() {
  const images = fs.readdirSync("cdn/products");

  await Promise.all(
    images
      .filter((imageName) => imageName.indexOf("_thumbnail") == -1)
      .map((imageName) => {
        const fileExtension =
          imageName.split(".")[imageName.split(".").length - 1] || "";

        let fileName = imageName.split(fileExtension)[0] || "";
        fileName = fileName.substring(0, fileName.length - 1);

        console.log(`Processing ${fileName}.${fileExtension}`);
        return sharp(`cdn/products/${fileName}.${fileExtension}`, {
          failOnError: false,
        })
          .rotate()
          .resize(280, 300)
          .toFile(`cdn/products/${fileName}_thumbnail.${fileExtension}`)
          .then(() => console.log(`Processed ${fileName}.${fileExtension}`))
          .catch(() => {
            console.log(`Error when processing ${fileName}.${fileExtension}`);
          });
      }),
  );
}

main();
