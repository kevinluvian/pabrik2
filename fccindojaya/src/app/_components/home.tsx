"use client";

import { Header } from "~/app/_components/header";
import { Footer } from "~/app/_components/footer";

const categories = [
  {
    name: "Semua Produk",
    href: "/all-products",
    imageSrc: "/home/foto1.jpeg",
  },
  {
    name: "Kancing",
    href: "/all-products",
    imageSrc: "/home/foto2.jpeg",
  },
  {
    name: "Resleting",
    href: "/all-products",
    imageSrc: "/home/foto6.jpeg",
  },
  {
    name: "Accessories",
    href: "/all-products",
    imageSrc: "/home/foto4.jpeg",
  },
  {
    name: "Barang Promo",
    href: "/under-construction",
    imageSrc: "/home/foto3.jpeg",
  },
];

export function HomeComponent() {
  return (
    <div className="bg-white">
      <Header />

      {/* Hero section */}
      <div className="pb-40 pt-16 sm:pb-40 sm:pt-24 lg:pb-40 lg:pt-24">
        <div className="relative mx-auto max-w-7xl px-4 sm:static sm:px-6 lg:px-8">
          <div className="relative z-10 sm:max-w-lg">
            <h1 className="text-4xl font-bold tracking-tight text-gray-900 sm:text-6xl">
              FCC Indo Jaya
            </h1>
            <p className="mt-4 text-xl text-gray-500">
              Bergerak dalam bidang jual-beli aksesoris garmen seperti
              resleting, kancing, mote-mote, karet, benang, stopper, gesper,
              alat tembakan merek, tali merek, lem tembak, peniti dan lain-lain.
              <br></br>
              <br></br> Jakarta, Indonesia
            </p>
          </div>
          <div>
            <div className="mt-10">
              {/* Decorative image grid */}
              <a
                target="_blank"
                href="https://wa.me/+6287846854410/?text=Halo FCC Indo Jaya, saya menemukan website anda dan ingin bertanya"
                className="relative z-10 inline-block rounded-md border border-transparent bg-indigo-600 px-8 py-3 text-center font-medium text-white hover:bg-indigo-700"
              >
                <div className="flex items-center justify-center">
                  <img
                    alt="Kirim Whatsapp ke FCC"
                    src="/home/wa.png"
                    className="mr-2 h-8 w-auto"
                  />
                  Hubungi Kami
                </div>
              </a>
              <div
                aria-hidden="true"
                className="pointer-events-none lg:absolute lg:inset-y-0 lg:mx-auto lg:w-full lg:max-w-7xl"
              >
                <div className="absolute top-[-70%] transform opacity-10 sm:left-1/2 sm:top-0 sm:opacity-100 lg:left-1/2 lg:top-[400px] lg:-translate-y-1/2">
                  <div className="flex items-center space-x-6 overflow-hidden lg:space-x-8">
                    <div className="grid shrink-0 grid-cols-1 gap-y-6 lg:gap-y-8">
                      <div className="h-64 w-44 overflow-hidden rounded-lg sm:opacity-0 lg:opacity-100">
                        <img
                          alt=""
                          src="/merk/fcc.png"
                          className="size-full object-contain"
                        />
                      </div>
                      <div className="h-64 w-44 overflow-hidden rounded-lg">
                        <img
                          alt=""
                          src="/home/foto2.jpeg"
                          className="size-full object-cover"
                        />
                      </div>
                    </div>
                    <div className="grid shrink-0 grid-cols-1 gap-y-6 lg:gap-y-8">
                      <div className="h-64 w-44 overflow-hidden rounded-lg">
                        {/* <img
                        alt=""
                        src=""
                        className="size-full object-cover"
                      /> */}
                      </div>
                      <div className="h-64 w-44 overflow-hidden rounded-lg">
                        <img
                          alt=""
                          src="/merk/sj.png"
                          className="size-full object-contain"
                        />
                      </div>
                      <div className="h-64 w-44 overflow-hidden rounded-lg">
                        <img
                          alt=""
                          src="/home/foto4.jpeg"
                          className="size-full object-cover"
                        />
                      </div>
                    </div>
                    <div className="grid shrink-0 grid-cols-1 gap-y-6 lg:gap-y-8">
                      <div className="h-64 w-44 overflow-hidden rounded-lg">
                        <img
                          alt=""
                          src="/merk/star.png"
                          className="size-full object-contain"
                        />
                      </div>
                      <div className="h-64 w-44 overflow-hidden rounded-lg">
                        <img
                          alt=""
                          src="/home/foto6.jpeg"
                          className="size-full object-cover"
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <main>
        {/* Category section */}
        <section
          aria-labelledby="category-heading"
          className="pt-24 sm:pt-32 xl:mx-auto xl:max-w-7xl xl:px-8"
        >
          <div className="px-4 sm:flex sm:items-center sm:justify-between sm:px-6 lg:px-8 xl:px-0">
            <h2
              id="category-heading"
              className="text-2xl font-bold tracking-tight text-gray-900"
            >
              Kategori Barang
            </h2>
            {/* <a
              href="#"
              className="hidden text-sm font-semibold text-indigo-600 hover:text-indigo-500 sm:block"
            >
              Browse all categories
              <span aria-hidden="true"> &rarr;</span>
            </a> */}
          </div>

          <div className="mt-4 flow-root">
            <div className="-my-2">
              <div className="relative box-content h-80 overflow-x-auto py-2 xl:overflow-visible">
                <div className="absolute flex space-x-8 px-4 sm:px-6 lg:px-8 xl:relative xl:grid xl:grid-cols-5 xl:gap-x-8 xl:space-x-0 xl:px-0">
                  {categories.map((category) => (
                    <a
                      key={category.name}
                      href={category.href}
                      className="relative flex h-80 w-56 flex-col overflow-hidden rounded-lg p-6 hover:opacity-75 xl:w-auto"
                    >
                      <span aria-hidden="true" className="absolute inset-0">
                        <img
                          alt=""
                          src={category.imageSrc}
                          className="size-full object-cover"
                        />
                      </span>
                      <span
                        aria-hidden="true"
                        className="absolute inset-x-0 bottom-0 h-2/3 bg-gradient-to-t from-gray-800 opacity-50"
                      />
                      <span className="relative mt-auto text-center text-xl font-bold text-white">
                        {category.name}
                      </span>
                    </a>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* <div className="mt-6 px-4 sm:hidden">
            <a
              href="#"
              className="block text-sm font-semibold text-indigo-600 hover:text-indigo-500"
            >
              Browse all categories
              <span aria-hidden="true"> &rarr;</span>
            </a>
          </div> */}
        </section>

        {/* Featured section */}
        <section
          aria-labelledby="social-impact-heading"
          className="mx-auto max-w-7xl px-4 pt-24 sm:px-6 sm:pt-32 lg:px-8"
        >
          <div className="relative overflow-hidden rounded-lg">
            <div className="absolute inset-0">
              <img
                alt=""
                src="https://tailwindui.com/plus/img/ecommerce-images/home-page-01-feature-section-01.jpg"
                className="size-full object-cover"
              />
            </div>
            <div className="relative bg-gray-900/75 px-6 py-32 sm:px-12 sm:py-40 lg:px-16">
              <div className="relative mx-auto flex max-w-3xl flex-col items-center text-center">
                <h2
                  id="social-impact-heading"
                  className="text-3xl font-bold tracking-tight text-white sm:text-4xl"
                >
                  <span className="block sm:inline">
                    Hubungi kami untuk pemesanan
                  </span>
                  <span className="block sm:inline"></span>
                </h2>
                <p className="mt-3 text-xl text-white">
                  Menerima pemesanan hanya secara grosir melalui WhatsApp
                  0878-4685-4410.
                </p>
                <a
                  href="https://wa.me/+6287846854410/?text=Halo FCC Indo Jaya, saya melihat website anda dan ingin bertanya"
                  target="_blank"
                  className="mt-8 flex w-full items-center justify-center rounded-md border border-transparent bg-white px-8 py-3 text-base font-medium text-gray-900 hover:bg-gray-300 sm:w-auto"
                >
                  <img
                    alt="Kirim Whatsapp ke FCC"
                    src="/home/wa.png"
                    className="mr-2 h-8 w-auto"
                  />
                  Kirim Pesan Whatsapp
                </a>
              </div>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
}
