import { Footer } from "~/app/_components/footer";
import { Header } from "~/app/_components/header";
import { api } from "~/trpc/server";
import { FolderArrowDownIcon } from "@heroicons/react/24/outline";
import Image from "next/image";

interface Product {
  id: number;
  name: string;
  href: string;
  imageSrc: string;
  imageAlt: string;
}

export default async function AllProducts() {
  const { products } = await api.product.GetProducts({ text: "from tRPC" });

  return (
    <div className="bg-gray-50">
      <Header />

      <div>
        <main>
          <div className="bg-white">
            <div className="mx-auto max-w-7xl px-4 pb-4 pt-8 sm:px-6 lg:px-8">
              <h1 className="pb-8 text-3xl font-bold tracking-tight text-gray-900">
                Semua Produk
              </h1>

              <a
                target="_blank"
                href="https://cdn.fccindojaya.co.id/katalog.pdf"
                className="relative z-10 inline-block rounded-md border border-transparent bg-indigo-600 px-8 py-2 text-center text-sm text-white hover:bg-indigo-700"
              >
                <div className="flex items-center justify-center">
                  <FolderArrowDownIcon
                    aria-hidden="true"
                    className="mr-2 size-6"
                  />
                  Download Katalog
                </div>
              </a>
            </div>
          </div>

          {/* Filters */}
          <section aria-labelledby="filter-heading">
            <h2 id="filter-heading" className="sr-only">
              Filters
            </h2>

            {/* Active filters */}
            <div className="bg-gray-100">
              <div className="mx-auto max-w-7xl px-4 py-3 sm:flex sm:items-center sm:px-6 lg:px-8">
                <h3 className="text-sm font-medium text-gray-500">
                  Produk
                  <span className="sr-only">, active</span>
                </h3>

                <div
                  aria-hidden="true"
                  className="hidden h-5 w-px bg-gray-300 sm:ml-4 sm:block"
                />
              </div>
            </div>
          </section>

          {/* Product grid */}
          <section
            aria-labelledby="products-heading"
            className="mx-auto max-w-2xl px-4 pb-16 pt-12 sm:px-6 sm:pb-24 sm:pt-16 lg:max-w-7xl lg:px-8"
          >
            <h2 id="products-heading" className="sr-only">
              Products
            </h2>

            <div className="grid grid-cols-1 gap-x-6 gap-y-10 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 xl:gap-x-8">
              {products.map((product) => (
                <a
                  key={product.id}
                  href={product.href}
                  target="_blank"
                  className="group"
                >
                  <img
                    alt={product.imageAlt}
                    src={product.imageSrc}
                    className="aspect-square w-full rounded-lg bg-gray-200 object-cover group-hover:opacity-75 xl:aspect-[7/8]"
                  />
                  <h3 className="sm:text-md mt-4 text-center text-lg text-gray-900">
                    {product.name}
                  </h3>
                  <p className="mt-1 text-lg font-medium text-gray-900">
                    {/* {product.price} */}
                  </p>
                </a>
              ))}
            </div>
          </section>
        </main>

        <Footer />
      </div>
    </div>
  );
}
