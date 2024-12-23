import Image from "next/image";

export default function Example() {
  return (
    <>
      {/*
        This example requires updating your template:

        ```
        <html class="h-full">
        <body class="h-full">
        ```
      */}
      <main className="relative isolate h-screen">
        <img
          alt=""
          src="/notfound.avif"
          className="absolute inset-0 -z-10 size-full object-cover object-top"
        />
        <div className="mx-auto max-w-7xl px-6 py-32 text-center sm:py-40 lg:px-8">
          <p className="text-base/8 font-semibold text-white">404</p>
          <h1 className="mt-4 text-balance text-5xl font-semibold tracking-tight text-white sm:text-7xl">
            Halaman sedang dalam pembangunan
          </h1>
          <p className="mt-6 text-pretty text-lg font-medium text-white/70 sm:text-xl/8">
            Silahkan hubungi kami langsung untuk pertanyaan
          </p>
          <div className="mt-10 flex justify-center">
            <a
              target="_blank"
              href="https://wa.me/+6287846854410/?text=Halo FCC Indo Jaya, saya membuka website anda dan ingin bertanya"
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
          </div>
        </div>
      </main>
    </>
  );
}
